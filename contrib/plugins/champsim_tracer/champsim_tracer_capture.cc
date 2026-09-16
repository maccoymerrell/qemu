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
#include "champsim_tracer_regmap.h"

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
Corpus *corpus_reg;      /* every register name QEMU used, and what it maps to */
Corpus *corpus_set;      /* the read and write SETS, per encoding */
Corpus *corpus_gen;      /* both decoders' sets, in the wire's own currency */
Corpus *corpus_alias;    /* what the alias refiners moved, per encoding */

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
            "#isa\tencoding\tatomic\timm\tvece\toprsz\tvkind\tvlane"
            "\tmemops\tfieldregs\tzero\tpcread\tea\tselfloop\tnrd\tnwr"
            "\tregs\n");
        corpus_reg = new Corpus(
            "CST_REGMAP_DUMP",
            "#isa\tencoding\tdir\tname\tgeneric\n");
        /*
         * THE SET, NOT ITS SIZE, AND KEYED ON THE ENCODING.
         *
         * CST_REGMAP_DUMP answers a question about the MAP, so it writes one
         * row per distinct (direction, name) for the whole run and keeps the
         * encoding only as a witness -- deliberately, and it says so.  That
         * leaves no corpus in which the register set QEMU stated for a given
         * encoding can be compared with anything: the statement corpus
         * carries the two SIZES, and a size cannot say WHICH register left.
         *
         * This corpus is that join.  One row per distinct
         * (isa, encoding, direction, set), so the same bytes decoding to two
         * different sets keep BOTH rows, and a set that changes between two
         * builds is a named difference rather than a count that moved.
         */
        corpus_set = new Corpus(
            "CST_DF_SET_DUMP",
            "#isa\tencoding\tdir\tn\tdigest\tnames\n");
        /*
         * BOTH DECODERS' REGISTER SETS, IN ONE CURRENCY, FROM ONE RUN.
         *
         * CST_DF_SET_DUMP carries QEMU's set in QEMU's own spellings, which is
         * the right answer for comparing two BUILDS of the QEMU side and the
         * wrong one for comparing the two DECODERS: the wire's src_regs[] and
         * dst_regs[] are GENERIC ids, the Capstone walk produces generic ids,
         * and a join between a TCG global's name and a generic id is not a
         * join.  So this corpus states both sides in the currency the wire
         * uses -- the QEMU side put through the same register map the wire
         * would put it through, the Capstone side as the walk produced it --
         * from the same run and the same window, keyed on the same encoding.
         *
         * A MEMBER THE MAP CANNOT TRANSLATE IS STILL A MEMBER.  It prints as
         * @unmapped:<qemu name>, an atom as its index, an undeclared env range
         * as its offset and extent.  Dropping any of them would make a set
         * compare equal to one that genuinely lacks it, and a REAL-LOST count
         * built on that is the discount R12.1 forbids.
         */
        corpus_gen = new Corpus(
            "CST_GEN_SET_DUMP",
            "#isa\tencoding\tside\tdir\tnraw\tnuniq\tnames\n");
        /*
         * WHICH SIDE OF THE REFINER CHAIN PRODUCED THE BRANCH TYPE.
         *
         * Three readings per encoding, so a row where they differ names the
         * encodings the alias surface is load-bearing for.  Deduplicated on
         * the whole row: the same bytes refine the same way every time, and a
         * repeat is a repeat.
         */
        corpus_alias = new Corpus(
            "CST_ALIAS_DUMP",
            "#isa\tencoding\tmnem\tbr_walk\tbr_alias\tbr_final"
            "\tcond_walk\tcond_alias\tcond_final"
            "\tnsrc_walk\tnsrc_alias\tnsrc_final\tndst_final\tmoved\n");
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

/*
 * Which register map to consult, from the name the run stamped its corpora
 * with.
 *
 * The capture has no other handle on the guest architecture: it is reached
 * from classification and from translation, neither of which is told.  An ISA
 * this build does not know answers TRACE_ISA_UNKNOWN, whose table is empty,
 * so every name reads UNMAPPED -- loudly wrong rather than quietly answered
 * out of some other target's spelling, which is the one failure that would
 * look like data.
 */
unsigned capture_isa_id()
{
    static unsigned id = UINT_MAX;

    if (id == UINT_MAX) {
        const char *n = isa_name();

        if (!strcmp(n, "x86_64") || !strcmp(n, "i386")) {
            id = TRACE_ISA_X86;
        } else if (!strcmp(n, "aarch64")) {
            id = TRACE_ISA_AARCH64;
        } else if (!strcmp(n, "riscv64") || !strcmp(n, "riscv32")) {
            id = TRACE_ISA_RISCV;
        } else if (!strcmp(n, "mipsel") || !strcmp(n, "mips")) {
            id = TRACE_ISA_MIPS;
        } else {
            id = TRACE_ISA_UNKNOWN;
        }
    }
    return id;
}

/*
 * The name QEMU gave provenance bit @bit, or NULL when the bit stands for
 * something that is not storage.
 *
 * Three namespaces share the one index: a bit below nregs is a TCG global and
 * carries the name the target registered it under; a bit at or above is an
 * env byte range, which resolves to a declared register-file entry's name
 * when the target declared its layout and to nothing when it did not; and
 * three bits are atoms.  A range with no declared name is NOT a gap in the
 * map -- there is no name for the map to carry a row for -- so it answers
 * NULL and @unnamed says so, keeping it apart from a name the map failed on.
 */
const char *prov_bit_name(unsigned bit, bool *is_atom)
{
    uint32_t atom = 0, off = 0, size = 0;

    if (is_atom) {
        *is_atom = false;
    }
    if (qemu_plugin_dataflow_prov_atom(bit, &atom)) {
        if (is_atom) {
            *is_atom = true;
        }
        return nullptr;
    }
    if (bit < qemu_plugin_dataflow_nregs()) {
        return qemu_plugin_dataflow_reg_name(bit, nullptr, nullptr);
    }
    if (qemu_plugin_dataflow_prov_field(bit, &off, &size)) {
        return qemu_plugin_dataflow_field_reg(off, size);
    }
    return nullptr;
}

/*
 * Score one register set against the map, and write a row for every distinct
 * (direction, name) the run has not written yet.
 *
 * Deduplicated by name rather than per encoding: the map is keyed on the
 * name, so a per-encoding row would repeat one fact a hundred thousand times
 * and answer no question the name row does not.  The encoding is kept as the
 * WITNESS on the first row that showed the name, which is what makes an
 * UNMAPPED row actionable instead of merely alarming.
 */
struct SeenReg {
    char name[64];
    char dir;
};

SeenReg *seen_regs;
unsigned n_seen_regs, cap_seen_regs;

void score_reg_name(const char *isa, const char *enc, char dir,
                    const char *name, unsigned *n_named, unsigned *n_mapped)
{
    unsigned isa_id = capture_isa_id();
    FILE *o = corpus_reg->get();
    uint8_t reg = REG_NONE;
    bool ok = cst_regmap_lookup(isa_id, name, &reg);

    (*n_named)++;
    if (ok) {
        (*n_mapped)++;
    }
    if (!o) {
        return;
    }
    for (unsigned i = 0; i < n_seen_regs; i++) {
        if (seen_regs[i].dir == dir && !strcmp(seen_regs[i].name, name)) {
            return;
        }
    }
    if (n_seen_regs == cap_seen_regs) {
        unsigned grown = cap_seen_regs ? cap_seen_regs * 2 : 128;
        SeenReg *p = (SeenReg *)realloc(seen_regs, grown * sizeof(*p));

        if (!p) {
            return;
        }
        seen_regs = p;
        cap_seen_regs = grown;
    }
    snprintf(seen_regs[n_seen_regs].name,
             sizeof(seen_regs[n_seen_regs].name), "%s", name);
    seen_regs[n_seen_regs].dir = dir;
    n_seen_regs++;

    const char *gn = ok ? generic_reg_name(reg) : nullptr;
    char buf[32];

    if (!ok) {
        snprintf(buf, sizeof(buf), "UNMAPPED");
    } else if (gn) {
        snprintf(buf, sizeof(buf), "%s", gn);
    } else {
        snprintf(buf, sizeof(buf), "REG_%u", (unsigned)reg);
    }
    fprintf(o, "%s\t%s\t%c\t%s\t%s\n", isa, enc, dir, name, buf);
}

void score_reg_set(const char *isa, const char *enc, char dir,
                   const uint64_t *set, unsigned nwords,
                   unsigned *n_named, unsigned *n_mapped)
{
    for (unsigned w = 0; w < nwords; w++) {
        uint64_t word = set[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;

            bool is_atom = false;
            const char *name = prov_bit_name(w * 64 + b, &is_atom);

            if (is_atom || !name) {
                continue;
            }
            score_reg_name(isa, enc, dir, name, n_named, n_mapped);
        }
    }
}

/*
 * A LABEL FOR EVERY MEMBER OF A SET, INCLUDING THE ONES THAT HAVE NO NAME.
 *
 * score_reg_set() walks the same bits and skips an atom and an undeclared env
 * range, because the question it asks is about the register MAP and neither is
 * a row the map owes.  A SET is a different question: a member with no name is
 * still a member, and a set printed without it would compare equal to a set
 * that genuinely lacks it.  So an atom prints as its index and an undeclared
 * range prints as its offset and extent -- neither is a register name, and
 * neither is silence.
 */
void prov_bit_label(unsigned bit, char *buf, size_t sz)
{
    uint32_t atom = 0, off = 0, size = 0;
    bool is_atom = false;
    const char *name = prov_bit_name(bit, &is_atom);

    if (name) {
        snprintf(buf, sz, "%s", name);
    } else if (is_atom && qemu_plugin_dataflow_prov_atom(bit, &atom)) {
        snprintf(buf, sz, "@atom%u", (unsigned)atom);
    } else if (qemu_plugin_dataflow_prov_field(bit, &off, &size)) {
        snprintf(buf, sz, "@env+%u:%u", (unsigned)off, (unsigned)size);
    } else {
        snprintf(buf, sz, "@bit%u", bit);
    }
}

/* Members past this are digested but not spelled; the row says how many. */
#define SET_NAMES_MAX 64

int label_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/*
 * Rows already written, keyed on "isa enc dir digest".
 *
 * The same encoding decodes millions of times to the same set; one row per
 * DISTINCT set is the whole content and the repetitions are noise.  Keyed on
 * the digest rather than on the encoding alone precisely so that an encoding
 * whose set DIFFERS between two occurrences keeps both rows.
 */
GHashTable *seen_sets;

void emit_reg_set(const char *isa, const char *enc, char dir,
                  const uint64_t *set, unsigned nwords)
{
    FILE *o = corpus_set->get();

    if (!o) {
        return;
    }

    char labels[SET_NAMES_MAX][40];
    unsigned n = 0, total = 0;
    uint64_t digest = 1469598103934665603ULL;   /* FNV-1a 64 */

    for (unsigned w = 0; w < nwords; w++) {
        uint64_t word = set[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;
            total++;
            if (n < SET_NAMES_MAX) {
                prov_bit_label(w * 64 + b, labels[n], sizeof(labels[n]));
                n++;
            }
        }
    }
    qsort(labels, n, sizeof(labels[0]), label_cmp);

    /*
     * The digest covers the SPELLED labels and the total.  Two sets that
     * agree on the first SET_NAMES_MAX members and differ beyond them share a
     * digest only if they also agree on size, which is stated in the row, so
     * an overflowed row is comparable on what it carries and says how much it
     * does not carry.
     */
    for (unsigned i = 0; i < n; i++) {
        for (const char *p = labels[i]; *p; p++) {
            digest = (digest ^ (unsigned char)*p) * 1099511628211ULL;
        }
        digest = (digest ^ ',') * 1099511628211ULL;
    }
    digest = (digest ^ total) * 1099511628211ULL;

    char key[192];

    snprintf(key, sizeof(key), "%s %s %c %016llx", isa, enc, dir,
             (unsigned long long)digest);
    if (seen_sets == nullptr) {
        seen_sets = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          g_free, nullptr);
    }
    if (g_hash_table_contains(seen_sets, key)) {
        return;
    }
    g_hash_table_add(seen_sets, g_strdup(key));

    char names[SET_NAMES_MAX * 41];
    size_t k = 0;

    names[0] = '\0';
    for (unsigned i = 0; i < n; i++) {
        int w = snprintf(names + k, sizeof(names) - k, "%s%s",
                         k ? "," : "", labels[i]);

        if (w < 0 || (size_t)w >= sizeof(names) - k) {
            break;
        }
        k += (size_t)w;
    }
    fprintf(o, "%s\t%s\t%c\t%u\t%016llx\t%s%s\n", isa, enc, dir, total,
            (unsigned long long)digest, k ? names : "-",
            total > n ? ",+MORE" : "");
}

/*
 * One member of QEMU's provenance set, in the WIRE's currency.
 *
 * prov_bit_label() spells a member as QEMU spells it, which is right for
 * comparing two QEMU-side builds and wrong for comparing the two DECODERS:
 * the Capstone walk produces generic ids and so does the wire.  This puts the
 * member through the same register map the wire would, so both sides of the
 * join speak generic.
 *
 * NOTHING IS DROPPED.  A name the map cannot translate is a real member and
 * prints as @unmapped:<name>; an atom and an undeclared env range print as
 * themselves.  A set that quietly omitted any of them would compare equal to
 * one that genuinely lacks it, and REAL-LOST measured against that is exactly
 * the discount R12.1 forbids.
 */
void gen_bit_label(unsigned bit, char *buf, size_t sz)
{
    uint32_t atom = 0, off = 0, size = 0;
    bool is_atom = false;
    const char *name = prov_bit_name(bit, &is_atom);

    if (name) {
        uint8_t reg = REG_NONE;

        if (cst_regmap_lookup(capture_isa_id(), name, &reg)) {
            const char *gn = generic_reg_name(reg);

            if (gn) {
                snprintf(buf, sz, "%s", gn);
            } else {
                snprintf(buf, sz, "REG_%u", (unsigned)reg);
            }
        } else {
            snprintf(buf, sz, "@unmapped:%s", name);
        }
    } else if (is_atom && qemu_plugin_dataflow_prov_atom(bit, &atom)) {
        snprintf(buf, sz, "@atom%u", (unsigned)atom);
    } else if (qemu_plugin_dataflow_prov_field(bit, &off, &size)) {
        snprintf(buf, sz, "@env+%u:%u", (unsigned)off, (unsigned)size);
    } else {
        snprintf(buf, sz, "@bit%u", bit);
    }
}

/* Rows already written, keyed "isa enc side dir names". */
GHashTable *seen_gen;

/*
 * One side's register set for one encoding and direction, spelled generic.
 *
 * @nraw is how many members the side actually produced and @nuniq how many
 * distinct spellings survive, so a row where two members share one generic
 * name says so instead of looking like a set that lost one.
 */
void emit_gen_set(const char *isa, const char *enc, char side, char dir,
                  char labels[][40], unsigned nraw, unsigned n)
{
    FILE *o = corpus_gen->get();

    if (!o) {
        return;
    }
    qsort(labels, n, sizeof(labels[0]), label_cmp);

    char names[SET_NAMES_MAX * 41];
    size_t k = 0;
    unsigned nuniq = 0;

    names[0] = '\0';
    for (unsigned i = 0; i < n; i++) {
        if (i && !strcmp(labels[i], labels[i - 1])) {
            continue;
        }
        nuniq++;
        int w = snprintf(names + k, sizeof(names) - k, "%s%s",
                         k ? "," : "", labels[i]);

        if (w < 0 || (size_t)w >= sizeof(names) - k) {
            break;
        }
        k += (size_t)w;
    }

    char key[256];

    snprintf(key, sizeof(key), "%s %s %c %c %s", isa, enc, side, dir,
             k ? names : "-");
    if (seen_gen == nullptr) {
        seen_gen = g_hash_table_new_full(g_str_hash, g_str_equal,
                                         g_free, nullptr);
    }
    if (g_hash_table_contains(seen_gen, key)) {
        return;
    }
    g_hash_table_add(seen_gen, g_strdup(key));

    fprintf(o, "%s\t%s\t%c\t%c\t%u\t%u\t%s%s\n", isa, enc, side, dir,
            nraw, nuniq, k ? names : "-", nraw > n ? ",+MORE" : "");
}

/* QEMU's side: walk the provenance bits, spell each one generic. */
void emit_gen_set_qemu(const char *isa, const char *enc, char dir,
                       const uint64_t *set, unsigned nwords)
{
    char labels[SET_NAMES_MAX][40];
    unsigned n = 0, total = 0;

    for (unsigned w = 0; w < nwords; w++) {
        uint64_t word = set[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;
            total++;
            if (n < SET_NAMES_MAX) {
                gen_bit_label(w * 64 + b, labels[n], sizeof(labels[n]));
                n++;
            }
        }
    }
    emit_gen_set(isa, enc, 'q', dir, labels, total, n);
}

/* The Capstone walk's side: the list the wire would publish today. */
void emit_gen_set_cap(const char *isa, const char *enc, char dir,
                      const uint8_t *regs, unsigned nregs)
{
    char labels[SET_NAMES_MAX][40];
    unsigned n = 0;

    for (unsigned i = 0; i < nregs && n < SET_NAMES_MAX; i++) {
        snprintf(labels[n], sizeof(labels[n]), "%s",
                 generic_reg_name_or_unknown(regs[i]));
        n++;
    }
    emit_gen_set(isa, enc, 'c', dir, labels, nregs, n);
}

} /* namespace */

void cst_capture_alias(const void *bytes, size_t nbytes, const char *mnem,
                       const struct InsnAliasSnap *walk,
                       const struct InsnAliasSnap *alias,
                       const struct InsnFields *f)
{
    if (!bytes || !nbytes || !walk || !alias || !f) {
        return;
    }
    corpora_init();

    FILE *o = corpus_alias->get();

    if (!o) {
        return;
    }

    char enc[2 * 32 + 1];

    hex_bytes(bytes, nbytes, enc, sizeof(enc));

    /*
     * WHICH REFINER MOVED IT, not merely that something did.  A scorer joining
     * this against the identity corpus's branch column has to be able to say
     * whether the alias surface produced the answer -- deleting it is what a
     * flip to QEMU's decode rule would do -- or whether the per-row .refine
     * did, which is a different callback with a different fate.
     */
    const char *moved = "none";

    if (walk->branch_type != alias->branch_type ||
        walk->branch_conditional != alias->branch_conditional ||
        walk->n_src_regs != alias->n_src_regs ||
        walk->n_dst_regs != alias->n_dst_regs) {
        moved = (alias->branch_type != f->branch_type ||
                 alias->branch_conditional != f->branch_conditional)
                ? "alias+refine" : "alias";
    } else if (alias->branch_type != f->branch_type ||
               alias->branch_conditional != f->branch_conditional) {
        moved = "refine";
    }

    fprintf(o, "%s\t%s\t%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%s\n",
            isa_name(), enc, mnem && mnem[0] ? mnem : "-",
            branch_type_name_or_unknown(walk->branch_type),
            branch_type_name_or_unknown(alias->branch_type),
            branch_type_name_or_unknown(f->branch_type),
            walk->branch_conditional ? 1u : 0u,
            alias->branch_conditional ? 1u : 0u,
            f->branch_conditional ? 1u : 0u,
            (unsigned)walk->n_src_regs, (unsigned)alias->n_src_regs,
            (unsigned)f->n_src_regs, (unsigned)f->n_dst_regs, moved);
}

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

    /*
     * The Capstone walk's register sets, in the currency the QEMU side is
     * written in by cst_capture_df_stmt().  Written here, from the same run
     * and the same window, so a scorer can join the two sides per encoding --
     * which is the join the destination flip's REAL-LOST bar is stated over
     * and the one no corpus carried.
     */
    if (corpus_gen->get()) {
        emit_gen_set_cap(isa, enc, 'r', f->src_regs, f->n_src_regs);
        emit_gen_set_cap(isa, enc, 'w', f->dst_regs, f->n_dst_regs);
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

    /*
     * FOUR CORPORA, ONE READER, AND NO CORPUS GATED ON ANOTHER'S REQUEST.
     *
     * This is the only place the dataflow status and the two provenance sets
     * are read, so the statement corpus, the register map, the QEMU-currency
     * set corpus and the generic-currency one are all fed from here.  They are
     * asked for independently, and the guard used to be `corpus_stmt` alone:
     * a run that asked for CST_GEN_SET_DUMP and not CST_DF_STMT_DUMP returned
     * before writing a single row, and got a file with a header and nothing
     * under it.
     *
     * That is exactly the silent false success this file's own header warns
     * about -- a corpus that was asked for and is not written -- and it was
     * caught by a scorer refusing an absent side rather than by the capture.
     * So the reader runs if ANY of its outputs was asked for, and each output
     * is written only where it is opened.
     */
    FILE *o = corpus_stmt->get();

    if (!o && !corpus_gen->get() && !corpus_reg->get() &&
        !corpus_set->get()) {
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
    unsigned n_named = 0, n_map = 0;
    for (unsigned i = 0; i < nf; i++) {
        const char *nm =
            qemu_plugin_dataflow_field_reg(frows[i].env_offset, frows[i].size);
        int w = snprintf(fields + fk, sizeof(fields) - fk, "%s%s",
                         fk ? "," : "", nm ? nm : "?");

        /*
         * The DECLARED register files reach a consumer only here.  A vector,
         * an x87 slot and an AVX-512 mask are env byte ranges, not TCG
         * globals, so their names never appear in the read and write
         * bitmaps -- and a map scored on those bitmaps alone would report a
         * clean zero while never having looked at the half of the namespace
         * the declarations exist for.
         */
        if (nm) {
            score_reg_name(isa_name(), enc, 'f', nm, &n_named, &n_map);
        }
        if (w < 0 || (size_t)w >= sizeof(fields) - fk) {
            break;
        }
        fk += (size_t)w;
    }

    /*
     * THE SYNTHETIC ADDRESS, AS ITS COMPONENTS.
     *
     * Rendered rather than counted, because the defect this column exists to
     * catch is a component that is present and wrong: two prefetches whose
     * encodings differ only in the scale field produce the same count and
     * different addresses.  Each component reads `<name><<shift`, with the
     * extend appended where one narrows the register, and the displacement
     * last.  A row the emulator refused reads "refused" -- it is not "-",
     * which means the instruction named no synthetic address at all.
     */
    char ea[256];
    size_t ek = 0;
    qemu_plugin_dataflow_ea earows[4];
    unsigned nea;

    for (unsigned i = 0; i < 4; i++) {
        earows[i] = qemu_plugin_dataflow_ea();
        earows[i].struct_size = sizeof(earows[i]);
    }
    nea = qemu_plugin_insn_synthetic_eas(tb, idx, earows, 4);
    if (nea > 4) {
        nea = 0;                /* more rows than asked for: nothing written */
    }
    ea[0] = '\0';
    for (unsigned i = 0; i < nea; i++) {
        for (unsigned k = 0; k < earows[i].n_parts && k < 4; k++) {
            const char *nm =
                qemu_plugin_dataflow_reg_name(earows[i].part_reg[k],
                                              nullptr, nullptr);
            uint32_t atom = 0;
            int w;

            if (!nm && qemu_plugin_dataflow_prov_atom(earows[i].part_reg[k],
                                                      &atom)) {
                nm = atom == QEMU_PLUGIN_DF_ATOM_ZERO ? "zero"
                   : atom == QEMU_PLUGIN_DF_ATOM_IMM  ? "imm"
                                                      : "const";
            }
            w = snprintf(ea + ek, sizeof(ea) - ek, "%s%s<<%u%s",
                         ek ? "+" : "", nm ? nm : "?",
                         earows[i].part_shift[k],
                         earows[i].part_ext[k] == QEMU_PLUGIN_DF_EA_EXT_UXTW
                             ? ":uxtw"
                         : earows[i].part_ext[k] == QEMU_PLUGIN_DF_EA_EXT_SXTW
                             ? ":sxtw"
                             : "");
            if (w < 0 || (size_t)w >= sizeof(ea) - ek) {
                break;
            }
            ek += (size_t)w;
        }
        int w = snprintf(ea + ek, sizeof(ea) - ek, "%s0x%llx",
                         ek ? "+" : "",
                         (unsigned long long)earows[i].disp);
        if (w < 0 || (size_t)w >= sizeof(ea) - ek) {
            break;
        }
        ek += (size_t)w;
    }
    if (!ek && st.n_synth_ea_refused) {
        snprintf(ea, sizeof(ea), "refused");
        ek = 7;
    }

    char vece[8];

    if (st.vec_vece == QEMU_PLUGIN_DF_VECE_NONE) {
        snprintf(vece, sizeof(vece), "-");
    } else {
        snprintf(vece, sizeof(vece), "%u", st.vec_vece);
    }

    /*
     * THE LANE KIND AND THE LANE IT SELECTS, in two columns and not one.
     *
     * A kind with no lane (a packed operation) and a lane the site refused to
     * state are different answers, and folding them into one column would
     * make the refusal read as an instruction that selects nothing -- the
     * shape this corpus exists to keep apart.  The lane column carries
     * `refused:<why>` when the decode site said so, so a masked arm moves the
     * refusal count and the kind column independently.
     */
    static const char *const kind_name[] = {
        "-", "uniform", "insert", "extract", "bcast",
    };
    const char *vkind =
        st.vec_kind < (sizeof(kind_name) / sizeof(kind_name[0]))
        ? kind_name[st.vec_kind] : "?";
    char vlane[24];

    if (st.vec_lane_refuse == QEMU_PLUGIN_DF_VEC_REFUSE_DYNAMIC) {
        snprintf(vlane, sizeof(vlane), "refused:dynamic");
    } else if (st.vec_lane_refuse == QEMU_PLUGIN_DF_VEC_REFUSE_COMPOSITE) {
        snprintf(vlane, sizeof(vlane), "refused:composite");
    } else if (st.vec_lane == QEMU_PLUGIN_DF_VEC_LANE_NONE) {
        snprintf(vlane, sizeof(vlane), "-");
    } else {
        snprintf(vlane, sizeof(vlane), "%d", st.vec_lane);
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
     * THE SELF-LOOP FAN-OUT UNIT, in one column that spells which kind of
     * unit it is.
     *
     * `iter:N` is an architectural iteration performing N accesses, `access:N`
     * an instruction with no iteration of its own whose unit is one access.
     * A bare N would make an x86 `rep stosb` and an AArch64 `setp` read alike
     * while a consumer must treat them differently -- one has an iteration
     * count to ask QEMU for and the other does not -- so the kind is spelled
     * and the two are counted apart.
     */
    char selfloop[24];

    if (st.self_loop_memops == 0) {
        snprintf(selfloop, sizeof(selfloop), "-");
    } else {
        snprintf(selfloop, sizeof(selfloop), "%s:%u",
                 st.self_loop_iterated ? "iter" : "access",
                 st.self_loop_memops);
    }

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
    /*
     * ONE WRITE PER ROW, and the row's last two columns are formatted first
     * to make that possible.
     *
     * The stream is line buffered so that a capture nothing closes still ends
     * on a whole row.  That only holds if a row is one write: with the set
     * sizes written by a second call the buffer sat holding a headless
     * fraction of a row between the two, and anything that flushed or
     * duplicated it there -- the compressor fork is the one this apparatus
     * makes -- put a bare tail in the corpus.  Measured at this tip, one such
     * row in riscv64/502 and one in mipsel/505 out of 593,198 and 144,612;
     * the scorer REFUSES a file containing one, which is the right answer and
     * is also why it had to be fixed rather than tolerated.
     */
    /*
     * THE REGISTER NAMES QEMU USED, AND HOW MANY THE MAP COULD READ.
     *
     * `named/mapped` over both sets.  NAMED counts the bits that resolved to
     * a register NAME -- a TCG global, or an env range inside a declared
     * register file -- and MAPPED counts the ones the wire's register map
     * translated.  The two differ exactly when this plugin and this emulator
     * were built from different register namespaces, which is the condition
     * a consumer must never see answered with a plausible id.
     *
     * An env range with no declared name is in NEITHER count: there is no
     * name, so there is nothing the map owes a row for, and counting it would
     * make the column report a gap no table can close.  The `fieldregs`
     * column beside it is what measures that population.
     */
    char sets[32];
    char regs[24];

    if (have_sets) {
        snprintf(sets, sizeof(sets), "%u\t%u", n_rd, n_wr);
        score_reg_set(isa_name(), enc, 'r', rd, 8, &n_named, &n_map);
        score_reg_set(isa_name(), enc, 'w', wr, 8, &n_named, &n_map);
        emit_reg_set(isa_name(), enc, 'r', rd, 8);
        emit_reg_set(isa_name(), enc, 'w', wr, 8);
        emit_gen_set_qemu(isa_name(), enc, 'r', rd, 8);
        emit_gen_set_qemu(isa_name(), enc, 'w', wr, 8);
        snprintf(regs, sizeof(regs), "%u/%u", n_named, n_map);
    } else {
        snprintf(sets, sizeof(sets), "-\t-");
        snprintf(regs, sizeof(regs), "-");
    }
    if (o) {
        fprintf(o,
                "%s\t%s\t%u\t%s\t%s\t%u\t%s\t%s\t%u\t%s\t%s\t%s\t%s\t%s\t%s"
                "\t%s\n",
                isa_name(),
                enc, (st.properties & QEMU_PLUGIN_DF_P_ATOMIC) ? 1u : 0u,
                k ? imm : "-", vece, st.vec_oprsz, vkind, vlane, st.n_memops,
                fk ? fields : "-", zero[0] ? zero : "-",
                pcbit == UINT_MAX ? "-" : (pc_rd ? "r" : "0"),
                ek ? ea : "-", selfloop, sets, regs);
    }
}

#endif /* CST_CAPTURE */
