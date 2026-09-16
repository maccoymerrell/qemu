/*
 * cst_referee — the external referee: the Capstone side of the tracer's
 * two-decoder comparison, produced offline from the encodings the corpus
 * already records.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHAT THIS IS FOR
 * ----------------
 * The tracer's acceptance rests on comparing two decoders per encoding.  For
 * as long as both columns were written from inside one running emulator, the
 * comparison was a dependent of the thing under test: when the wire stopped
 * consulting the Capstone operand walk, the walk stopped being called, every
 * Capstone row stopped being written, and the whole-population REAL-LOST bar
 * went from a number to "no subject" -- which is worse than a red, because a
 * missing subject looks like nothing at all.
 *
 * Checking Capstone belongs OUTSIDE QEMU.  This binary reads the (isa,
 * encoding) keys out of a QEMU-side corpus, disassembles those bytes with its
 * OWN copy of the pinned Capstone the tree names, runs the tracer's own
 * operand walk over the result, and writes the Capstone-side corpora in the
 * same format the in-process arm wrote them in.  It links no plugin .so and
 * no emulator.  Nothing done to the tracer's Capstone dependency can make
 * this stop answering.
 *
 * VERSION PARITY IS PART OF THE BAR.  Two Capstones disagree with each other
 * about plenty; a referee running a different one would turn version noise
 * into decoder disagreement and every arbitration written against it would be
 * about the wrong thing.  So this tool links subprojects/capstone -- the same
 * build cst_decode and isaxcheck use -- refuses to run if the library it
 * loaded is not the one its headers describe, and STAMPS the wrap revision,
 * the header version and the runtime version into every corpus it writes.
 *
 * THE BOUNDARY IS THE REAL ONE.  disas/capstone.c is compiled into this
 * binary, so `cap_disas_raw_detail()` applies exactly the workarounds it
 * applies for the plugin -- the PEXTR access flag, the MIPS MSA and unaligned
 * access==0 rows, the x86 store-move destinations.  A workaround that stops
 * working shows up here as a disagreement appearing, which is the only way it
 * can show up at all; a referee that re-derived Capstone detail on its own
 * would have to reimplement them and would then be scoring its own copy.
 */

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

#include <unistd.h>

#include <capstone/capstone.h>

#include "qemu/qemu-plugin.h"

#include "cst_referee_fields.h"

/* Implemented by disas/capstone.c, compiled into this tool. */
extern "C" bool cap_disas_raw_detail(int cap_arch, unsigned int cap_mode,
                                     const uint8_t *data, size_t data_size,
                                     uint64_t pc,
                                     struct qemu_plugin_insn_info *out);

#ifndef CST_REFEREE_CAPSTONE_PIN
#define CST_REFEREE_CAPSTONE_PIN "unstamped"
#endif

namespace {

/* The address every encoding is decoded at.  Fixed, because a pc that moved
 * would put a pc-relative operand's rendered target into the row and the row
 * is keyed on the encoding alone. */
const uint64_t kDecodePc = 0x100000;

struct Options {
    const char *isa = nullptr;
    const char *in = nullptr;
    const char *out_dir = nullptr;
    bool selftest = false;
};

void usage(FILE *f)
{
    fputs(
"cst_referee --isa ISA --in CORPUS --out-dir DIR\n"
"cst_referee --selftest\n"
"\n"
"  --isa       x86_64 | aarch64 | riscv64 | mipsel\n"
"  --in        a QEMU-side capture corpus; its column 1 is the ISA and its\n"
"              column 2 the encoding.  Any of them will do -- the identity,\n"
"              statement or generic-set corpus all carry the same key.\n"
"  --out-dir   where the Capstone-side corpora are written.\n"
"\n"
"Writes srcenc/opc/mech/gen_c/alias/facts for the ISA, each stamped with the\n"
"input corpus's own #so line (the build whose encodings are being scored) and\n"
"a #referee line naming the Capstone this binary ran.\n", f);
}

bool hex_nibble(char c, unsigned *out)
{
    if (c >= '0' && c <= '9') {
        *out = (unsigned)(c - '0');
    } else if (c >= 'a' && c <= 'f') {
        *out = (unsigned)(c - 'a') + 10;
    } else if (c >= 'A' && c <= 'F') {
        *out = (unsigned)(c - 'A') + 10;
    } else {
        return false;
    }
    return true;
}

/* "4889e5" -> the three bytes.  False for an odd length or a non-hex digit:
 * a key this tool cannot turn back into bytes is not a key it may skip
 * silently, and main() counts every one. */
bool unhex(const std::string &s, std::vector<uint8_t> *out)
{
    if (s.empty() || (s.size() & 1) || s.size() > 2 * 64) {
        return false;
    }
    out->clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned hi, lo;

        if (!hex_nibble(s[i], &hi) || !hex_nibble(s[i + 1], &lo)) {
            return false;
        }
        out->push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

struct Input {
    std::string stamp;                  /* the corpus's own #so line */
    std::vector<std::string> encodings; /* deduplicated, in first-seen order */
    unsigned long rows = 0;             /* data rows for this ISA */
    unsigned long other_isa = 0;        /* data rows for some other ISA */
};

/*
 * Read the (isa, encoding) keys out of a QEMU-side corpus.
 *
 * Deduplicated because the same bytes decode the same way every time -- the
 * in-process arm wrote one row per translation and every scorer downstream
 * already collapses them on the key -- and because decoding a million copies
 * of `mov %rsp,%rbp` measures the loop, not the decoder.
 */
bool read_input(const char *path, const char *isa, Input *out, std::string *err)
{
    FILE *f = fopen(path, "r");

    if (!f) {
        *err = std::string(path) + ": " + strerror(errno);
        return false;
    }

    std::unordered_set<std::string> seen;
    char *line = nullptr;
    size_t cap = 0;
    ssize_t n;

    while ((n = getline(&line, &cap, f)) > 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }
        if (n == 0) {
            continue;
        }
        if (!strncmp(line, "#so ", 4)) {
            out->stamp = line + 4;
            continue;
        }
        if (line[0] == '#') {
            continue;
        }

        char *tab1 = strchr(line, '\t');

        if (!tab1) {
            continue;
        }
        *tab1 = '\0';

        char *enc = tab1 + 1;
        char *tab2 = strchr(enc, '\t');

        if (tab2) {
            *tab2 = '\0';
        }
        if (strcmp(line, isa)) {
            out->other_isa++;
            continue;
        }
        out->rows++;
        if (seen.insert(enc).second) {
            out->encodings.push_back(enc);
        }
    }
    free(line);
    fclose(f);
    return true;
}

/*
 * A corpus that was asked for and is absent, empty, or about a different ISA
 * is a refusal.  Stated here rather than downstream because a referee that
 * writes an empty Capstone column reproduces exactly the failure it was built
 * to end: a join with one arm, reading as a total loss on every encoding.
 */
bool check_input(const Input &in, const char *path, const char *isa,
                 std::string *err)
{
    if (in.stamp.empty()) {
        *err = std::string(path) + ": no #so stamp.  An unstamped corpus "
               "cannot say which build its encodings came from, and a join "
               "across builds is the frozen-arm failure.";
        return false;
    }
    if (in.rows == 0) {
        *err = std::string(path) + ": no data rows for isa " + isa;
        if (in.other_isa) {
            *err += " (but " + std::to_string(in.other_isa) +
                    " rows for another ISA -- wrong --isa, or wrong corpus)";
        }
        return false;
    }
    if (in.encodings.empty()) {
        *err = std::string(path) + ": rows but no encodings";
        return false;
    }
    return true;
}

void set_corpus(const char *var, const std::string &dir, const char *stem,
                const char *isa)
{
    std::string p = dir + "/" + stem + "_" + isa + ".tsv";

    setenv(var, p.c_str(), 1);
}

int run_selftest(void);

} /* namespace */

int main(int argc, char **argv)
{
    Options o;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "--selftest")) {
            o.selftest = true;
        } else if (!strcmp(a, "--isa") && i + 1 < argc) {
            o.isa = argv[++i];
        } else if (!strcmp(a, "--in") && i + 1 < argc) {
            o.in = argv[++i];
        } else if (!strcmp(a, "--out-dir") && i + 1 < argc) {
            o.out_dir = argv[++i];
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "cst_referee: unknown argument %s\n", a);
            usage(stderr);
            return 2;
        }
    }

    /*
     * VERSION PARITY, CHECKED BEFORE ANYTHING IS WRITTEN.
     *
     * cs_version() answers for the library this process actually loaded.  If
     * that is not the library these headers describe, every disagreement this
     * run reports is version noise wearing a decoder's clothes, and the right
     * answer is to refuse rather than to publish it with a caveat.
     */
    int cs_major = 0, cs_minor = 0;

    cs_version(&cs_major, &cs_minor);
    if (cs_major != CS_API_MAJOR || cs_minor != CS_API_MINOR) {
        fprintf(stderr,
                "cst_referee: linked Capstone is %d.%d but these headers are "
                "%d.%d.  A comparison run against a different Capstone turns "
                "version differences into decoder disagreements; refusing.\n",
                cs_major, cs_minor, CS_API_MAJOR, CS_API_MINOR);
        return 3;
    }

    if (o.selftest) {
        return run_selftest();
    }

    if (!o.isa || !o.in || !o.out_dir) {
        usage(stderr);
        return 2;
    }

    Input in;
    std::string err;

    if (!read_input(o.in, o.isa, &in, &err) ||
        !check_input(in, o.in, o.isa, &err)) {
        fprintf(stderr, "cst_referee: %s\n", err.c_str());
        return 4;
    }

    std::string dir = o.out_dir;
    char note[512];

    snprintf(note, sizeof(note),
             "#referee capstone_wrap=%s headers=%d.%d runtime=%d.%d "
             "source=%s",
             CST_REFEREE_CAPSTONE_PIN, CS_API_MAJOR, CS_API_MINOR,
             cs_major, cs_minor, o.in);

    /*
     * The corpora carry the INPUT's #so stamp, not this binary's.
     *
     * A corpus answers for the build whose encodings it scores, and these
     * encodings are the emulator's.  Stamping the referee's own build id here
     * would make the two sides of the join look like two builds and the
     * scorer would refuse a pair that is in fact matched.  Which binary
     * produced the Capstone column is a separate fact and gets its own line.
     */
    setenv("CST_CORPUS_STAMP", in.stamp.c_str(), 1);
    setenv("CST_CORPUS_NOTE", note, 1);
    setenv("CST_CAPTURE_ISA", o.isa, 1);

    set_corpus("CST_SRC_ENC_DUMP", dir, "srcenc", o.isa);
    set_corpus("CST_OPC_ENC_DUMP", dir, "opc", o.isa);
    set_corpus("CST_SRC_MECH_DUMP", dir, "mech", o.isa);
    set_corpus("CST_GEN_SET_DUMP", dir, "gen_c", o.isa);
    set_corpus("CST_ALIAS_DUMP", dir, "alias", o.isa);

    if (!cstref_init(o.isa)) {
        fprintf(stderr, "cst_referee: no tracer tables for isa %s\n", o.isa);
        return 4;
    }

    std::string facts_path = dir + "/facts_" + o.isa + ".tsv";
    FILE *facts = fopen(facts_path.c_str(), "w");

    if (!facts) {
        fprintf(stderr, "cst_referee: cannot write %s: %s\n",
                facts_path.c_str(), strerror(errno));
        return 4;
    }
    fprintf(facts, "#so %s\n%s\n", in.stamp.c_str(), note);
    fputs("#isa\tencoding\tmnem\topcode\tbranch\tcond\tatomic\tregdeps"
          "\taddrdeps\tveclanes\tlanekind\tlanebytes\tmaxloads\tmaxstores"
          "\tnsrc\tndst\n", facts);

    unsigned long decoded = 0, boundary_refused = 0, unhexable = 0;
    unsigned long unclassified = 0;
    std::vector<uint8_t> bytes;

    for (const std::string &e : in.encodings) {
        if (!unhex(e, &bytes)) {
            unhexable++;
            continue;
        }

        qemu_plugin_insn_info info;

        if (!cap_disas_raw_detail(cstref_cap_arch(), cstref_cap_mode(),
                                  bytes.data(), bytes.size(), kDecodePc,
                                  &info)) {
            /*
             * Capstone declined these bytes.  That is an ANSWER -- the column
             * is "Capstone has nothing here" -- and the scorers have a bucket
             * for it (CAPSTONE-BLANK).  It is counted and not written,
             * exactly as the in-process arm behaved: the capture hooks fire
             * from inside the walk and the walk was never entered.
             */
            boundary_refused++;
            continue;
        }

        CstRefFacts f;

        if (!cstref_decode(kDecodePc, bytes.data(), bytes.size(), &info, &f)) {
            fprintf(stderr, "cst_referee: decode refused for %s\n", e.c_str());
            fclose(facts);
            return 5;
        }
        decoded++;
        if (!f.ok) {
            unclassified++;
        }

        fprintf(facts,
                "%s\t%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u"
                "\t%u\t%u\n",
                o.isa, e.c_str(),
                info.mnemonic[0] ? info.mnemonic : "-",
                cstref_opcode_name(f.opcode),
                cstref_branch_name(f.branch_type),
                f.branch_conditional ? 1u : 0u, f.is_atomic ? 1u : 0u,
                f.has_reg_deps ? 1u : 0u, f.has_addr_deps ? 1u : 0u,
                f.has_vec_lanes ? 1u : 0u,
                (unsigned)f.lane_mask_kind, (unsigned)f.lane_bytes,
                (unsigned)f.max_dep_loads, (unsigned)f.max_dep_stores,
                (unsigned)f.n_src_regs, (unsigned)f.n_dst_regs);
    }
    fclose(facts);

    printf("cst_referee %s: %lu rows -> %lu distinct encodings; "
           "decoded %lu, capstone-blank %lu, unclassified %lu, "
           "unparsable keys %lu\n",
           o.isa, in.rows, (unsigned long)in.encodings.size(), decoded,
           boundary_refused, unclassified, unhexable);
    printf("  %s\n", note);
    printf("  stamp carried from the input: %s\n", in.stamp.c_str());

    /*
     * A run that decoded nothing FAILS.
     *
     * Every corpus this tool writes would exist, parse, and contain a header
     * and no rows -- which is precisely the shape that made the bar read "no
     * subject" instead of a number.  The one thing a referee may never do is
     * produce a well-formed silence.
     */
    if (decoded == 0) {
        fprintf(stderr,
                "cst_referee: %lu encodings and not one decoded.  A Capstone "
                "column with no rows is the failure this tool exists to end; "
                "refusing to call that a result.\n",
                (unsigned long)in.encodings.size());
        return 6;
    }
    if (unhexable) {
        fprintf(stderr,
                "cst_referee: %lu key(s) were not hex bytes and were not "
                "scored.\n", unhexable);
        return 7;
    }
    return 0;
}

namespace {

/*
 * The selftest, because a scorer nobody has seen refuse is a scorer nobody
 * knows can.  Every arm below is run and its expected outcome asserted; a
 * silently-passing arm is reported as a failure of the selftest itself.
 */
struct SelftestCase {
    const char *isa;
    const char *enc;
    bool expect_boundary_ok;
    const char *expect_mnem;    /* nullptr = do not check */
};

int run_selftest(void)
{
    int fail = 0, ran = 0;

    /* Arm 1: every ISA the tracer has tables for initialises, and names a
     * Capstone arch. */
    for (const char *isa : {"x86_64", "aarch64", "riscv64", "mipsel"}) {
        ran++;
        if (!cstref_init(isa)) {
            printf("FAIL init %s\n", isa);
            fail++;
        } else if (cstref_cap_arch() < 0) {
            printf("FAIL cap_arch %s\n", isa);
            fail++;
        } else {
            printf("ok   init %s arch=%d mode=0x%x\n", isa, cstref_cap_arch(),
                   cstref_cap_mode());
        }
    }

    /* Arm 2: an ISA there are no tables for is REFUSED, not defaulted. */
    ran++;
    if (cstref_init("sparc64")) {
        printf("FAIL an unknown ISA initialised\n");
        fail++;
    } else {
        printf("ok   unknown isa refused\n");
    }

    /* Arm 3: real encodings decode, and the boundary's verdict is the
     * boundary's -- both directions, so neither is assumed. */
    const SelftestCase cases[] = {
        /*
         * The x86 mnemonics are AT&T-suffixed because QEMU's Capstone is
         * configured for AT&T syntax; asserting the Intel spelling here would
         * be asserting a boundary this tree does not have.
         */
        { "x86_64",  "4889e5",   true,  "movq" },   /* mov %rsp,%rbp */
        { "x86_64",  "c3",       true,  "retq" },
        { "aarch64", "e00301aa", true,  nullptr },  /* mov x0, x1 */
        { "riscv64", "93000000", true,  nullptr },  /* addi x1,x0,0 */
        { "mipsel",  "21100000", true,  nullptr },  /* addu $2,$0,$0 */
        /*
         * Capstone DOES decode this one -- as `udf #0` -- and saying so is
         * the point: the tracer's corpus carries no row for it because QEMU's
         * admission gate declines it, which is a fact about the QEMU side.
         * Pinning the Capstone verdict here keeps the two from being
         * confused for one another.
         */
        { "aarch64", "00000000", true,  "udf"  },
        /* Bytes no ISA decodes: the boundary declines, and the decline is
         * an answer the scorers have a bucket for. */
        { "riscv64", "ffffffff", false, nullptr },
    };

    for (const SelftestCase &c : cases) {
        ran++;
        if (!cstref_init(c.isa)) {
            printf("FAIL selftest init %s\n", c.isa);
            fail++;
            continue;
        }

        std::vector<uint8_t> b;

        if (!unhex(c.enc, &b)) {
            printf("FAIL unhex %s\n", c.enc);
            fail++;
            continue;
        }

        qemu_plugin_insn_info info;
        bool ok = cap_disas_raw_detail(cstref_cap_arch(), cstref_cap_mode(),
                                       b.data(), b.size(), kDecodePc, &info);

        if (ok != c.expect_boundary_ok) {
            printf("FAIL %s %s: boundary %s, expected %s\n", c.isa, c.enc,
                   ok ? "decoded" : "declined",
                   c.expect_boundary_ok ? "decoded" : "declined");
            fail++;
            continue;
        }
        if (!ok) {
            printf("ok   %s %s declined at the boundary\n", c.isa, c.enc);
            continue;
        }
        if (c.expect_mnem && strcmp(info.mnemonic, c.expect_mnem)) {
            printf("FAIL %s %s: mnemonic %s, expected %s\n", c.isa, c.enc,
                   info.mnemonic, c.expect_mnem);
            fail++;
            continue;
        }

        CstRefFacts f;

        if (!cstref_decode(kDecodePc, b.data(), b.size(), &info, &f)) {
            printf("FAIL %s %s: the walk refused\n", c.isa, c.enc);
            fail++;
            continue;
        }
        printf("ok   %s %s -> %s %s src=%u dst=%u\n", c.isa, c.enc,
               info.mnemonic, cstref_opcode_name(f.opcode),
               (unsigned)f.n_src_regs, (unsigned)f.n_dst_regs);
    }

    /* Arm 4: a key that is not hex bytes is refused rather than truncated. */
    for (const char *bad : { "4889e", "zz", "" }) {
        std::vector<uint8_t> b;

        ran++;
        if (unhex(bad, &b)) {
            printf("FAIL unhex accepted \"%s\"\n", bad);
            fail++;
        } else {
            printf("ok   unhex refused \"%s\"\n", bad);
        }
    }

    /* Arm 5: the input reader's four refusals, each on a real file. */
    {
        char tmpl[] = "/tmp/cstrefXXXXXX";
        int fd = mkstemp(tmpl);

        if (fd < 0) {
            printf("FAIL selftest could not make a temp file\n");
            fail++;
        } else {
            FILE *f = fdopen(fd, "w");

            fputs("#so plugin=aa emulator=bb\n#isa\tencoding\n"
                  "x86_64\t4889e5\tmov\n", f);
            fclose(f);

            struct {
                const char *isa;
                bool expect_ok;
                const char *what;
            } arms[] = {
                { "x86_64", true,  "a matching corpus is accepted" },
                { "mipsel", false, "a corpus for another ISA is refused" },
            };

            for (auto &a : arms) {
                Input in;
                std::string err;

                ran++;
                bool read_ok = read_input(tmpl, a.isa, &in, &err);
                bool ok = read_ok && check_input(in, tmpl, a.isa, &err);

                if (ok != a.expect_ok) {
                    printf("FAIL %s (got %s)\n", a.what,
                           ok ? "accepted" : err.c_str());
                    fail++;
                } else {
                    printf("ok   %s\n", a.what);
                }
            }

            /* An unstamped corpus is refused. */
            FILE *g = fopen(tmpl, "w");

            fputs("#isa\tencoding\nx86_64\t4889e5\n", g);
            fclose(g);
            {
                Input in;
                std::string err;

                ran++;
                bool ok = read_input(tmpl, "x86_64", &in, &err) &&
                          check_input(in, tmpl, "x86_64", &err);
                if (ok) {
                    printf("FAIL an unstamped corpus was accepted\n");
                    fail++;
                } else {
                    printf("ok   unstamped corpus refused\n");
                }
            }

            /* A corpus with a stamp and no data rows is refused. */
            g = fopen(tmpl, "w");
            fputs("#so plugin=aa emulator=bb\n#isa\tencoding\n", g);
            fclose(g);
            {
                Input in;
                std::string err;

                ran++;
                bool ok = read_input(tmpl, "x86_64", &in, &err) &&
                          check_input(in, tmpl, "x86_64", &err);
                if (ok) {
                    printf("FAIL an empty corpus was accepted\n");
                    fail++;
                } else {
                    printf("ok   empty corpus refused\n");
                }
            }
            unlink(tmpl);
        }
    }

    /* A missing file is refused. */
    {
        Input in;
        std::string err;

        ran++;
        if (read_input("/nonexistent/cst_referee", "x86_64", &in, &err)) {
            printf("FAIL a missing corpus was accepted\n");
            fail++;
        } else {
            printf("ok   missing corpus refused\n");
        }
    }

    printf("\ncst_referee selftest: %d arms, %d failure(s)\n", ran, fail);
    if (ran < 20) {
        printf("FAIL the selftest itself ran only %d arms\n", ran);
        return 1;
    }
    return fail ? 1 : 0;
}

} /* namespace */
