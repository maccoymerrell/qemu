/*
 * IR dataflow cross-check (irdf=1).
 *
 * Author: Maccoy Merrell
 *
 * See champsim_tracer_irdf.h for what this is and, more to the point, what
 * it is not: nothing here reaches the wire.
 *
 * The comparison is between two namespaces that do not line up, and the
 * whole difficulty is refusing to paper over that.  QEMU names TCG globals;
 * the tracer names architectural registers.  Where the two agree on a name
 * the mapping is read from the tracer's OWN generated tables, so it cannot
 * drift from the vocabulary the tracer publishes.  Where they do not, the
 * register is counted into a named bucket and reported -- never dropped.  A
 * silently discarded register is a disagreement that scores as agreement,
 * which is the one outcome that would make this instrument worse than
 * having none.
 */
#include <algorithm>
#include <inttypes.h>
#include <string.h>
#include <mutex>
#include <vector>

#include <glib.h>

#include "champsim_tracer.h"
#include "champsim_tracer_irdf.h"
#include "champsim_tracer_mnemonics.h"
#include "champsim_tracer_generic_ids.h"

/* The dataflow header carries no linkage guard of its own -- neither does
 * qemu-plugin.h, which champsim_tracer.h wraps the same way.  Without this
 * the plugin asks the loader for a mangled name and fails to dlopen. */
extern "C" {
#include <qemu-plugin-dataflow.h>
}

namespace {

std::mutex g_lock;

bool g_on = false;

/* Same predicate the decode TU uses; it is file-local there. */
inline bool reg_key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

/* One shot at initialisation; a failure disables the instrument and says so. */
bool        g_tried   = false;
bool        g_live    = false;
unsigned    g_nregs   = 0;
unsigned    g_nwords  = 0;
/*
 * How wide a PROVENANCE set is, which is not how wide a register set is: a
 * provenance also carries the env byte ranges the block interned and the
 * load-data bits, both of which live above the globals.  QEMU is asked
 * rather than assumed, because the width is a property of its namespace.
 */
unsigned    g_prov_words = 0;

/* Room for the accesses of one instruction; more than any encoding here
 * makes, and a count above it is refused rather than read short. */
#define QEMU_PLUGIN_IRDF_MAX_MEMOPS 16
#define QEMU_PLUGIN_IRDF_MAX_FIELDS 16
const char *g_refusal = nullptr;        /* why, if !g_live */

/* TCG global index -> GenericRegId, or REG_ID_COUNT for "no tracer word".
 *
 * The names are QEMU's own static strings (the TCG globals table lives as
 * long as the process), so the pointer is the string -- and std::string is
 * not available here at all: include/qemu/ctype.h shadows the system
 * <ctype.h> on the plugin include path, so every libstdc++ header that
 * pulls <cctype> fails to compile.  That is why no TU in this plugin uses
 * std::string, and why the tallies below are GHashTables. */
std::vector<uint8_t>     g_gen_of_reg;
std::vector<const char *> g_reg_names;

/*
 * A global that is not architectural state at all.
 *
 * QEMU allocates TCG globals for its OWN bookkeeping -- the address and
 * value a load-exclusive stashed, the condition and target a MIPS branch
 * carries into its delay slot -- and those are not registers the guest ISA
 * has, so the tracer is right to have no word for them.  Before this list
 * existed they were counted `unmapped` and the WHOLE instruction was then
 * discarded unscored, which is how every `ldxr`/`stxr` and every MIPS
 * conditional branch fell out of the comparison.
 *
 * EXCLUDING is not the same as INVENTING a mapping, and the difference is
 * the one the file is built around: a fabricated fold would score a wrong
 * answer as agreement, whereas declaring a QEMU-internal temp out of the
 * architectural namespace removes a name neither side ever claimed.  The
 * count is reported separately anyway, so a reader can see how many rows
 * became scoreable because of this list and can disbelieve it if they
 * disagree with an entry.
 */
bool nonarch_global(const char *n)
{
    static const char *const kInternal[] = {
        /* target/arm: the load-exclusive monitor.  Not architectural. */
        "exclusive_addr", "exclusive_val", "exclusive_high",
        /* target/mips: the delay-slot branch machinery, and the LL monitor. */
        "bcond", "btarget", "lladdr", "llval",
        /* target/riscv: the load-reserved monitor. */
        "load_res", "load_val",
    };
    for (const char *k : kInternal) {
        if (!strcmp(n, k)) {
            return true;
        }
    }
    return false;
}

/* Counters.  Every instruction lands in exactly one of the first three. */
uint64_t g_n_declined = 0;   /* extraction incomplete: QEMU refused to answer */
uint64_t g_n_helper   = 0;   /* went through a helper: the walk cannot see in */
uint64_t g_n_fields   = 0;   /* touched CPU state the register namespace omits */
uint64_t g_n_agree    = 0;
uint64_t g_n_disagree = 0;
uint64_t g_n_unmapped = 0;   /* had a register neither side can name in common */
uint64_t g_n_nonarch  = 0;   /* scored, but a QEMU-internal temp was excluded */

/*
 * The memop arm.
 *
 * The register arm above declines an instruction the moment QEMU's
 * extraction is short of whole -- a helper, a field, an overflow.  The
 * memop question must NOT inherit those refusals: n_mem_reads /
 * n_mem_writes come from qemu_plugin_insn_dataflow_status(), which counts
 * the qemu_ld / qemu_st ops the target emitted and answers even when the
 * register extraction overflowed.  So every translated instruction is
 * scored here, including the ones the register arm had to set aside.
 *
 * What is compared is the tracer's TEMPLATE-STATIC claim (max_dep_loads /
 * max_dep_stores, walked out of the Capstone operand list) against the
 * number of memory ops QEMU's own translation of the same bytes emitted.
 * Neither is the runtime count -- a predicated or self-looping instruction
 * issues fewer or more, and CST_FID_N_LOADS / N_STORES carry that -- so the
 * comparison is of PRESENCE and of the static bound, which is exactly what
 * the dep-mask layout is built from.
 *
 * A helper is the one case where QEMU's zero is not evidence of absence:
 * an access performed inside a helper emits no qemu_ld/qemu_st, so it is
 * counted apart rather than called a tracer overclaim.
 */
uint64_t g_m_agree     = 0;
uint64_t g_m_disagree  = 0;
uint64_t g_m_helper_lo = 0;  /* ir says fewer, and the insn calls a helper */

/*
 * The CP-H ceiling arm.
 *
 * The question this answers is the one that has to be answered BEFORE any
 * Capstone-derived dependency classifier is deleted: of the instructions a
 * workload actually EXECUTES, what fraction can the emitter-stated dependency
 * model describe exactly, what fraction only as an over-approximation, and
 * what fraction not at all.  A retirement cannot be better than that number,
 * and quoting a static opcode count in its place would answer a different
 * question -- the encodings a target CAN decode, weighted equally, when what
 * a consumer feels is the instructions that RUN, weighted by how often.
 *
 * So both are counted.  The static tallies below are per TRANSLATION; the
 * scoreboards are incremented by an inline op on every EXECUTION, which is
 * where the weighting comes from and why this is not another translate-time
 * count wearing a dynamic label.
 */
uint64_t g_h_static[3]  = {0, 0, 0};   /* EXACT / APPROX / OPAQUE */
uint64_t g_h_static_unknown = 0;       /* sum of n_helper_unknown */
uint64_t g_h_static_unbounded = 0;     /* sum of n_helper_unbounded */
uint64_t g_h_static_calls   = 0;       /* translated insns calling a helper */
struct qemu_plugin_scoreboard *g_h_sb[3] = {nullptr, nullptr, nullptr};
bool g_h_sb_failed = false;
/*
 * The PER-REFINER arm -- the measurement the retirement verdict is made of.
 *
 * The question is not "is .dep_refine right".  It is, per refiner: does
 * anything downstream lose an edge if the row stops carrying it.  There are
 * two ways a row can be losable and they are counted apart, because they have
 * different proofs:
 *
 *   INERT   the refiner published exactly what a consumer assumes when there
 *           is no HAS_REG block at all -- every destination depending on every
 *           input, every stored value depending on every input, and the same
 *           memop shape the operand walk left.  The wire contract says a
 *           missing block means precisely that (champsim_tracer_mnemonics.h:
 *           "false (default) -> consumers fall back to implicit all-to-all
 *           dataflow"), so such a row costs bytes and states nothing.  This
 *           is decidable WITHOUT the IR: it is a property of the refiner's
 *           own output against the format's own default.
 *   NARROWS the shape is unchanged but at least one mask is a proper SUBSET
 *           of all-inputs.  An edge exists that the default does not have,
 *           so the row is load-bearing unless something else states it.
 *   RESHAPES the refiner changed the memop shape itself -- added store slots
 *           (a push's implicit stores), removed load slots (an address
 *           compute's phantom load).  The default cannot express a shape it
 *           was never given; these rows are load-bearing by construction.
 *   WIDENS  a mask carries a bit the all-inputs mask does not.  That is not a
 *           refinement of anything and would be a defect; counted so that a
 *           zero here is measured rather than assumed.
 *
 * The second decode runs with the refiner WITHHELD (dep_refine_set_suppressed)
 * rather than by reimplementing the default here, so the two sides differ in
 * exactly one thing: whether the refiner ran.
 */
struct RefTally {
    uint64_t rows;
    uint64_t inert;        /* published the default explicitly: bytes for nothing */
    uint64_t silent;       /* published no block at all: costs nothing, says nothing */
    uint64_t narrows;
    uint64_t reshapes;
    uint64_t widens;
    uint64_t h_class[3];   /* the CP-H model of the same instruction */
    uint64_t ma_agree, ma_disagree;   /* address provenance vs the emitters */
    uint64_t md_agree, md_disagree;   /* store-data provenance              */
    uint64_t mu_agree, mu_disagree;   /* load-to-use edge                   */
};
GHashTable *g_reftally = nullptr;      /* char* -> RefTally* */
/*
 * The SHAPE the operand walk handed each refiner, tallied per refiner.
 *
 * A verdict of INERT says the row stated nothing; it does not say why, and
 * the two whys have different remedies.  A refiner can publish the default
 * because the instruction genuinely has nothing to narrow, or because its
 * own shape precondition did not hold and it bailed -- and a refiner whose
 * precondition never holds is not imprecise, it is unreachable.  The shape
 * is recorded rather than the predicate re-tested, so the evidence is what
 * the walk produced and not a second copy of the refiner's own reasoning.
 */
GHashTable *g_refshape = nullptr;      /* char* -> count */
const char *g_cur_refiner = nullptr;   /* set for the duration of one insn */

RefTally *reftally_for(const char *name)
{
    if (!name) {
        return nullptr;
    }
    if (!g_reftally) {
        g_reftally = g_hash_table_new_full(g_str_hash, g_str_equal,
                                           g_free, g_free);
    }
    RefTally *t = (RefTally *)g_hash_table_lookup(g_reftally, name);
    if (!t) {
        t = g_new0(RefTally, 1);
        g_hash_table_insert(g_reftally, g_strdup(name), t);
    }
    return t;
}

uint64_t all_inputs_of(const InsnFields *f)
{
    uint64_t m = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        m |= (uint64_t)1 << i;
    }
    for (uint8_t i = 0; i < f->max_dep_loads; i++) {
        m |= (uint64_t)1 << (f->n_src_regs + i);
    }
    if (f->has_immediate) {
        m |= (uint64_t)1 << (f->n_src_regs + f->max_dep_loads);
    }
    return m;
}

uint64_t g_m_nostatus  = 0;  /* status refused outright */
/* Truncation census.  STATUS section 5 records 0.011%/0.001% as a FLOOR:
 * these count what this workload actually hit, per instruction and as a
 * distinct-opcode set, so the floor stops being quoted as a bound. */
uint64_t g_t_fields    = 0;
uint64_t g_t_writes    = 0;
uint64_t g_t_prov      = 0;

/*
 * The memop DEPENDENCY arm -- CP-M's reader.
 *
 * The arm above compares HOW MANY accesses each side says an instruction
 * makes.  This one compares what each says the accesses DEPEND ON, which is
 * the fact the counts cannot carry and the one a consumer schedules on:
 *
 *   address   which registers computed it.  QEMU states this because `addr`
 *             is a parameter of tcg_gen_qemu_ld/st_*; the tracer states it
 *             structurally, from the base/index/segment registers of
 *             Capstone's MEM operand.  Two independent derivations of one
 *             fact, which is what makes the comparison worth taking.
 *   data      what produced a stored value.  Same on the QEMU side; on the
 *             tracer side it comes from .dep_refine, so an encoding with no
 *             refiner has no claim to compare and is set aside by name.
 *   load-use  whether a destination depends on the VALUE LOADED rather than
 *             on the address registers.  This is the edge that did not exist
 *             on the QEMU side at all until the emitters stated it.
 *
 * SCOPED TO ONE LOAD AND ONE STORE, deliberately.  Both sides list accesses
 * in their own order -- QEMU's is emission order, the tracer's is Capstone
 * operand order -- and nothing has established that those agree when an
 * instruction has several of a kind.  Comparing slot k to slot k on faith
 * would score a mis-pairing as a disagreement and, worse, could score two
 * mis-pairings as an agreement.  Multi-access encodings are counted apart
 * until the ordering is proven rather than assumed.
 *
 * The IMMEDIATE is out of scope on both arms: an address displacement is a
 * constant, QEMU's provenance records constants as nothing (a value from a
 * constant came from no register), and the tracer's addr masks never set the
 * imm bit either.  Nothing is being papered over -- there is no claim on
 * either side to compare.
 */
uint64_t g_ma_agree    = 0;   /* address provenance: agree                  */
uint64_t g_ma_disagree = 0;
uint64_t g_md_agree    = 0;   /* store-data provenance: agree               */
uint64_t g_md_disagree = 0;
uint64_t g_mu_agree    = 0;   /* load-to-use edge: both sides have it or not */
uint64_t g_mu_disagree = 0;
uint64_t g_mq_norecord = 0;   /* qemu declined to hand over whole records   */
uint64_t g_mq_mismatch = 0;   /* records disagreed with the op counts       */
uint64_t g_mq_multi    = 0;   /* several accesses of a kind: ordering unproven */
uint64_t g_mq_field    = 0;   /* a provenance naming state the tracer cannot */
uint64_t g_mq_unmapped = 0;   /* a global with no tracer word               */
uint64_t g_mq_nodep    = 0;   /* tracer published no dep block to compare   */
uint64_t g_mq_helper   = 0;   /* a helper could have done it where no op says */
GHashTable *g_masigs = nullptr;
GHashTable *g_mdsigs = nullptr;
GHashTable *g_musigs = nullptr;

GHashTable *g_sigs = nullptr;             /* char* -> count, boxed */
GHashTable *g_unmapped_by_name = nullptr;
GHashTable *g_msigs = nullptr;            /* memop disagreement signatures */
GHashTable *g_trunc_by_mnem = nullptr;    /* opcodes that overflowed 8/8 */

void tally(GHashTable **t, const char *key)
{
    if (!*t) {
        *t = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, nullptr);
    }
    gsize n = GPOINTER_TO_SIZE(g_hash_table_lookup(*t, key)) + 1;
    g_hash_table_insert(*t, g_strdup(key), GSIZE_TO_POINTER(n));
}

/*
 * Where QEMU's TCG-global name and the tracer's word are the same fact under
 * two spellings, folded -- and every entry here is a MEASUREMENT, taken from
 * this instrument's own namespace dump on that ISA, not a guess.  The
 * comment this replaces promised exactly that ("per-ISA folds get added as
 * each ISA is measured, not guessed") and then only x86_64 was ever
 * measured, so three of the four ISAs ran with a namespace map nobody had
 * looked at.  What that cost is recorded on each entry.
 *
 * x86_64: the flags live in four globals holding a lazy representation --
 *   cc_op selects how cc_dst/cc_src/cc_src2 are to be read.  All four ARE
 *   the flags register.
 *
 * aarch64: NZCV is four separate one-bit globals, which is the same shape as
 *   x86's cc_* quartet and gets the same fold.  The tracer's word for them
 *   is REG_FLAGS (the aarch64 table reaches it through the GDB-stub name
 *   "cpsr", which is not what the TCG global is called).
 *
 * mipsel: the accumulators.  QEMU names them HI0..HI3 / LO0..LO3; the
 *   tracer's GDB-stub names are "hi" and "lo", so only the DSP-free pair
 *   would ever have matched by name and in fact none did.
 *
 * pc, on every target that has a global for it: the tracer's REG_PC.  Both
 *   sides drop REG_PC before scoring -- whether QEMU materialises the pc is
 *   a property of where the TB ended -- but mapping it is still what lets
 *   the instruction be SCORED at all rather than discarded as unmapped.
 *
 * Left unmapped ON PURPOSE, and reported by name: x86's segment BASES (a
 * base is not the selector the tracer models) and the MPX bound registers.
 * Inventing a mapping for a register the tracer has no concept of would
 * score a fabrication as agreement.
 */
}  /* namespace -- reopened below; fold_nonarch is shared with the qdep TU,
    * because two copies of a name map are two maps that drift apart. */

/*
 * QEMU'S OWN LOWERING STATE, WHICH MUST NEVER BECOME A WORD (R16).
 *
 * A TCG global is not automatically a register.  Some of them hold state
 * the ARCHITECTURE does not have, minted so one translation block can hand
 * a value to the next: mips evaluates a branch condition into `bcond` and
 * its target into `btarget` because the condition is computed BEFORE the
 * delay slot and consumed AFTER it, and `hflags` is QEMU's cached digest of
 * CP0 mode bits, recomputed by compute_hflags() rather than named by any
 * instruction.  Nothing in the MIPS ISA can read or write any of the three.
 *
 * The read-list vocabulary census used to report them as `global-word`, the
 * reason whose coverage path is "needs a name mapping" -- so 2,894 of
 * mipsel's 2,978 drops read as a vocabulary gap somebody should close, when
 * closing it would put QEMU's lowering on the wire and violate the one rule
 * this arc is built on.  They are their own outcome now, with the reason,
 * and the census stops asking for a fix that would be a defect.
 *
 * This is NOT the place for state the architecture does have and this file
 * has no word for.  The LL/SC reservation is the live example -- mips
 * `lladdr`/`llval`, riscv `load_res`/`load_val` -- and it stays counted as a
 * vocabulary gap, because MIPS LLbit and the RISC-V reservation set are
 * ISA-defined and an SC really does read them.  They need a generic id
 * allocated, which is a wire-vocabulary decision and not a fold.
 */
const char *nonarch_lowering_reason(TraceISA isa, const char *name)
{
    if (isa != TRACE_ISA_MIPS) {
        return nullptr;
    }
    if (!strcmp(name, "bcond")) {
        return "mips delay-slot branch condition, computed before the "
               "delay slot and consumed after it (translate.c:1178)";
    }
    if (!strcmp(name, "btarget")) {
        return "mips delay-slot branch target, same mechanism as bcond "
               "(translate.c:1177)";
    }
    if (!strcmp(name, "hflags")) {
        return "QEMU's cached digest of CP0 mode bits, recomputed by "
               "compute_hflags() and named by no instruction "
               "(translate.c:1180)";
    }
    return nullptr;
}

uint8_t fold_nonarch(const char *name)
{
    if (!strcmp(name, "cc_op") || !strcmp(name, "cc_dst") ||
        !strcmp(name, "cc_src") || !strcmp(name, "cc_src2")) {
        return REG_FLAGS;                       /* x86_64 */
    }
    if (!strcmp(name, "NF") || !strcmp(name, "ZF") ||
        !strcmp(name, "CF") || !strcmp(name, "VF")) {
        return REG_FLAGS;                       /* aarch64 */
    }
    if (!strcmp(name, "pc")) {
        return REG_PC;
    }
    /*
     * The last two spellings a '/'-alias split cannot reach, because QEMU and
     * the GDB stub disagree about the NAME rather than about the form.  Both
     * were found by reading this instrument's own dump, not predicted.
     *
     * aarch64: the TCG global is "lr"; the GDB core feature calls x30 "x30",
     *   which is what the tracer's table carries.
     * riscv64: the TCG global is "x8/s0", spelling x8 by its ABI name; the
     *   RISC-V GDB stub calls x8 "fp", which is what the table carries.
     */
    if (!strcmp(name, "lr")) {
        return REG_LR;
    }
    /*
     * The THREAD POINTER, on the two targets that hold it in a place no
     * name reaches.
     *
     * Both are DECLARED REGFILE names rather than TCG globals -- aarch64's
     * TPIDR_EL0 lives in cp15 and mipsel's is active_tc.CP0_UserLocal --
     * and neither appears in its target's GDB-stub namespace (#240), so the
     * generated QEMU-indexed table cannot carry a row for either: a
     * QEMU_ONLY_REG_IDS rule naming a register the namespace does not
     * contain is dead by construction and the generator rejects it.  This
     * map is the place a QEMU spelling with no table row meets its word,
     * which is exactly what it already does for "lr" and "x8/s0" above.
     *
     * REG_TLS is the vocabulary's own word for this register and names both
     * of them by name (champsim_tracer_generic_ids.h: "the thread pointer
     * -- AArch64 TPIDR_EL0 / MIPS CP0_UserLocal"), so nothing is invented
     * here; the spelling is being connected to a word that already exists.
     */
    if (!strcmp(name, "tpidr_el0") ||    /* aarch64, cp15.tpidr_el0   */
        !strcmp(name, "userlocal")) {    /* mipsel, CP0_UserLocal     */
        return REG_TLS;
    }
    /*
     * The FP/SIMD EXECUTION-ENABLE GATE, which is a source of every
     * instruction it gates (R7.4) and which QEMU resolves at translation
     * time -- so it arrives as a DECLARED RANGE stated by
     * fp_access_check_only(), never as a global an op walk could find.
     *
     * REG_SYSFPEN is the vocabulary's existing word for it and names it in
     * those terms already (champsim_tracer_generic_ids.h: "FP / vector
     * execution-enable gate"), so this connects a spelling to a word rather
     * than inventing either.  CPTR_EL2 and CPTR_EL3 are the same gate at the
     * higher exception levels and would reach the same word; the statement
     * names CPACR_EL1 alone and says why at the site.
     */
    if (!strcmp(name, "cpacr_el1")) {
        return REG_SYSFPEN;
    }
    /*
     * XCR0, x86's extended control register, DECLARED by
     * target/i386/tcg/translate.c and absent from the i386 GDB stub's
     * namespace -- the same shape as the thread pointers above, so the
     * generated QEMU-indexed table cannot carry a row for it.
     *
     * REG_SYS is the vocabulary's residual privileged-file word and XCR0 is
     * a privileged control register with no finer class in it, so this
     * connects a spelling to a word rather than inventing either.  `xgetbv`
     * is the witness: it reads XCR0 and returns it, and the wire has always
     * published REG_SYS for it.
     */
    if (!strcmp(name, "xcr0")) {
        return REG_SYS;
    }
    /*
     * THE DESCRIPTOR-TABLE AND TASK REGISTERS -- x86's GDTR, IDTR, LDTR and
     * TR -- DECLARED by target/i386/tcg/translate.c and absent from the i386
     * GDB stub's namespace, the same shape as XCR0 above.
     *
     * These four are not a new word and not a new spelling.  REG_SYSMMU is
     * the vocabulary's word for "the state address translation reads", and
     * names these four registers outright
     * (qemu-plugin.h: "x86 GDTR / IDTR / LDTR / TR, the descriptor tables a
     * segment load and an interrupt reach"); the spellings are the ones
     * disas/capstone.c's own table already answers in
     * (`{ "gdtr", QEMU_PLUGIN_SYSREG_MMU }` and its three siblings).  So this
     * connects the QEMU-side declaration to the word the boundary was already
     * producing, which is what lets the boundary go.
     */
    if (!strcmp(name, "gdtr") || !strcmp(name, "idtr") ||
        !strcmp(name, "ldtr") || !strcmp(name, "tr")) {
        return REG_SYSMMU;
    }
    /*
     * THE MPX BOUND REGISTERS.
     *
     * BND<n> is one 128-bit architectural register and QEMU keeps it as TWO
     * TCG globals, `bnd<n>_lb` and `bnd<n>_ub` over bnd_regs[n].lb and .ub.
     * Splitting a register into a lower and an upper half is a storage
     * decision -- the same shape as x86's FPSW.TOP living outside env->fpus,
     * which target/i386 declares under one name for the same reason -- so
     * both spellings answer to the one word.
     *
     * REG_BOUND<n> already IS that word: the operand walk publishes
     * X86_REG_BND<n> as REG_BOUND<n> today.  This connects QEMU's spelling to
     * it; the i386 GDB stub has no bound registers, so the generated
     * QEMU-indexed table can carry no row for them.
     */
    if (!strncmp(name, "bnd", 3) && name[3] >= '0' && name[3] <= '3' &&
        (!strcmp(name + 4, "_lb") || !strcmp(name + 4, "_ub"))) {
        return REG_BOUND0 + (name[3] - '0');
    }
    /*
     * THE MIPS MSA VECTOR FILE, `w0`..`w31`.
     *
     * Declared by target/mips/tcg/msa_translate.c and absent from the MIPS
     * GDB-stub namespace -- QEMU's mips gdbstub carries org.gnu.gdb.mips.cpu
     * with f0..f31 and no MSA feature at all -- so the generated
     * QEMU-indexed table cannot carry a row for these: a rule naming a
     * register the namespace does not contain is dead by construction and
     * the generator rejects it.  Same shape as the thread pointers and XCR0
     * above.
     *
     * REG_VEC<n> is the vocabulary's word for a vector register file and is
     * ALREADY what the wire publishes for MSA, so this connects a spelling
     * to an existing word rather than inventing either.
     *
     * NAMED, NOT SILENT: MSA `w<n>` and scalar FP `f<n>` are ONE STORAGE in
     * the architecture -- f<n> is the low 64 bits of w<n>, which is why
     * msa_translate_init() maps msa_wr_d[n*2] onto fpu_f64[n] -- and the
     * wire gives them different words, REG_VEC<n> and REG_FPR<n>.  A
     * consumer joining them will miss the dependence between `add.d $f0`
     * and `addv.b $w0`.  That is a VOCABULARY question about what the two
     * words mean, it predates this map (the operand walk answers it the same
     * way), and it is recorded here rather than settled in passing.
     */
    if (name[0] == 'w' && name[1] >= '0' && name[1] <= '9') {
        char *end = NULL;
        long idx = strtol(name + 1, &end, 10);

        if (end != NULL && *end == '\0' && idx >= 0 && idx <= 31) {
            return (uint8_t)(REG_VEC0 + idx);
        }
    }
    /*
     * The SOFTFLOAT STATUS FILE, one spelling on both targets that have one.
     *
     * `float_status` is QEMU's own container for the rounding mode, the
     * accrued exception flags and the NaN rules -- the contents of the
     * architectural FP control-and-status register, held where the softfloat
     * code can reach them.  AArch64 splits it into an array by operating
     * regime and RISC-V keeps one; both are the same architectural file, and
     * the generator's standing rule for a control-and-status file that
     * cannot be split into control and status halves is REG_FCSR.
     */
    if (!strncmp(name, "fp_status", 9)) {
        /*
         * A PREFIX, because a declared file of more than one element is
         * spelled base-plus-index: AArch64's eight elements arrive as
         * "fp_status0".."fp_status7" and RISC-V's single one as "fp_status".
         * Every one of them is the same architectural register, so the
         * element number is not a discriminator here and matching the base
         * is matching the register.  Nothing else in either target's
         * namespace begins with these nine characters.
         */
        return REG_FCSR;
    }
    /*
     * GCR_EL1, the tag-generation control.  REG_SYS is the word the wire
     * already publishes for it; the declaration is what lets QEMU's own read
     * of the range say the same thing.
     */
    if (!strcmp(name, "gcr_el1")) {
        return REG_SYS;
    }
    /*
     * MIDR_EL1, the main ID register.
     *
     * It arrives by a different door from every spelling above: not as a
     * declared env range but as a NAME, because QEMU holds it in the ARMCPU
     * object and resolves `mrs xN, midr_el1` at translation time
     * (ARM_CP_CONST, translate-a64.c).  The spelling is therefore
     * ARMCPRegInfo::name, which is UPPER case, where a declared regfile name
     * is lower -- two namespaces, matched exactly as each spells itself
     * rather than case-folded, so a future collision is a compile-visible
     * duplicate rather than a silent one.
     *
     * REG_SYSID is the vocabulary's word for the read-only implementation
     * constants and already names this class (RISC-V VLENB/mvendorid/marchid,
     * MIPS PRId/Config, aarch64 fcr0 sit on it), and REG_SYSID is what the
     * wire has always published for this instruction -- the census row this
     * closes is a published REG_SYSID with nothing in QEMU's union to justify
     * it.  Nothing is invented here; a spelling meets a word that exists.
     */
    if (!strcmp(name, "MIDR_EL1")) {
        return REG_SYSID;
    }
    /*
     * DCZID_EL0 and FPCR, the two AArch64 system registers `mrs` reaches
     * through an ACCESSOR rather than through a constant or an env load.
     * They arrive by the same door MIDR_EL1 does -- ARMCPRegInfo::name,
     * UPPER case, stated at translate-a64.c's readfn arm -- so the same
     * exact-spelling match applies and a case fold is still refused.
     *
     * Neither spelling can reach the generated table: it is keyed on QEMU's
     * GDB-stub namespace, and AArch64's stub carries `fpcr` (lower case, a
     * different spelling of the same register) and no system-register
     * feature at all.
     *
     * DCZID_EL0 is a read-only implementation constant -- the DC ZVA block
     * size -- which is what REG_SYSID names, and REG_SYSID is what the wire
     * has always published for `mrs xN, dczid_el0`.  FPCR is the FP
     * control-and-status file, REG_FCSR, which is both what the wire
     * publishes for `mrs xN, fpcr` and what the table's own `fpcr` row
     * carries.  Two spellings meeting words that exist.
     */
    if (!strcmp(name, "DCZID_EL0")) {
        return REG_SYSID;
    }
    if (!strcmp(name, "FPCR")) {
        return REG_FCSR;
    }
    /*
     * The MIPS FP CONDITION CODES.  QEMU keeps all eight as bits of the
     * fpu_fcr31 global and gen_compute_branch1() states the one the branch
     * tests by name; the GDB-stub namespace carries only the container
     * (`fcr31`), so the generated table cannot hold a row for a member --
     * the same position tpidr_el0 and userlocal are in above.
     *
     * REG_PRED<n> is the vocabulary's own word for a one-bit predicate and
     * REG_PRED0/REG_PRED1 are what the wire publishes for `bc1t $fcc0` and
     * `bc1t $fcc1`, so the member meets the word it already had.
     */
    if (!strncmp(name, "fcc", 3) && name[3] >= '0' && name[3] <= '7' &&
        name[4] == '\0') {
        return (uint8_t)(REG_PRED0 + (name[3] - '0'));
    }
    if (!strcmp(name, "x8/s0")) {
        return REG_FP_REG;
    }
    /* mipsel: HI<n>/LO<n> are the accumulator halves.  REG_ACC<n> names the
     * LOW half and REG_ACCHI<n> the HIGH half of the same accumulator, so
     * the pairing is exact rather than a fold onto one word. */
    bool hi = !strncmp(name, "HI", 2), lo = !strncmp(name, "LO", 2);
    if ((hi || lo) && name[2] >= '0' && name[2] <= '3' && name[3] == '\0') {
        unsigned n = (unsigned)(name[2] - '0');
        return (uint8_t)((hi ? REG_ACCHI0 : REG_ACC0) + n);
    }
    return REG_ID_COUNT;
}

namespace {

/*
 * Reverse of build_qemu_reg_reverse_index(): a QEMU register name -> id.
 *
 * QEMU spells a TCG global whatever its target's translator passed to
 * tcg_global_mem_new, and two of the four targets do not use the bare
 * architectural name.  RISC-V builds a COMPOUND name, "x5/t0", joining the
 * numeric and ABI spellings; MIPS suffixes the accumulator INDEX, "HI0".
 * The tracer's tables carry the GDB-stub name -- "t0", "hi" -- so a plain
 * whole-string compare misses both.  On riscv64 it missed the ENTIRE
 * general-purpose register file: measured at ab9f839075, 1 of 101 globals
 * mapped and the instrument scored 0 instructions on every probe, an ISA
 * reporting no disagreements because it was making no comparisons.
 *
 * So the compare is tried against the whole name and then against each
 * '/'-separated alias within it.  An alias is matched EXACTLY (after the
 * split), never as a prefix: a prefix rule would let "x1" match "x1h", the
 * upper half of a 128-bit register, and fold two different globals onto one
 * word.
 */
bool name_matches(const char *tracer_name, const char *qemu_name)
{
    if (!strcasecmp(tracer_name, qemu_name)) {
        return true;
    }
    for (const char *p = qemu_name; *p; ) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len == strlen(tracer_name) &&
            !strncasecmp(tracer_name, p, len)) {
            return true;
        }
        if (!slash) {
            break;
        }
        p = slash + 1;
    }
    return false;
}

}  /* namespace -- reopened below; the next function is shared. */

/*
 * The QEMU-register-name -> generic-slot lookup, out of the anonymous
 * namespace because the branch arm in champsim_tracer_qemu_ident.cc resolves
 * the same thing for a different reason: it has a TCG global index naming an
 * indirect branch's target, and needs to know whether that register is the
 * link register.  One authority, two readers.
 *
 * THE NAME IS QEMU'S AND SO IS THE TABLE IT IS LOOKED UP IN.  This used to
 * walk the CAPSTONE-KEYED array and read the `.qemu_reg` a row happened to
 * carry, which made the answer depend on a second decoder having a constant
 * for the register -- and where it has none, the walk ran off the end and
 * the caller was told the register has no generic word.  That is not a
 * property of the register: x86's `fctrl` is the x87 control word whether or
 * not `X86_REG_FCTRL` exists, and it does not.  The QEMU-indexed rows have
 * one entry per register in QEMU's own namespace and ARE the authority for
 * what generic slot a register is (see QemuRegRow); the Capstone-keyed table
 * is a route to them.  So the lookup reads the authority, and the route --
 * along with the Capstone reachability of the register -- stops deciding
 * whether the question can be answered at all.
 *
 * Keyed by NAME because that is all a caller holds: `insn_dataflow_reg_name`
 * and `insn_dataflow_field_reg` answer in QEMU's GDB-stub spelling without a
 * feature.  Two registers in different features sharing a spelling and
 * disagreeing about their slot would make the name an ambiguous key, so that
 * case REFUSES rather than taking the first -- the same rule
 * build_qemu_reg_reverse_index() applies in the other direction.
 */
uint8_t generic_for_qemu_name(const char *name)
{
    uint8_t found = REG_ID_COUNT;

    if (!active_qemu_regs || active_qemu_regs_count == 0 || !name) {
        return REG_ID_COUNT;
    }
    for (unsigned i = 0; i < active_qemu_regs_count; i++) {
        const QemuRegRow *row = &active_qemu_regs[i];

        /*
         * REG_NONE IS NOT AN ANSWER, and it is 0, so it passes every
         * `< REG_ID_COUNT` test while meaning the opposite.  A QREG_UNNAMED
         * row whose role the vocabulary has no class for (x86 `efer`,
         * `fs_base`) carries it, and returning it seats a src slot spelled
         * REG_NONE that a published mask then points at -- measured, on
         * `mov %fs:0x28,%rax`, whose load-address mask named REG_NONE
         * before this test existed.  Skipped like a row with no id at all,
         * which is what the Capstone-keyed walk did by having no row.
         */
        if (row->n_regs != 0 || !row->name ||
            row->reg_id == REG_NONE || row->reg_id >= REG_ID_COUNT) {
            continue;
        }
        if (!name_matches(row->name, name)) {
            continue;
        }
        if (found != REG_ID_COUNT && found != row->reg_id) {
            return REG_ID_COUNT;        /* ambiguous spelling: no answer */
        }
        found = row->reg_id;
    }
    return found;
}

namespace {

void irdf_init_locked(void)
{
    g_tried = true;

    if (!qemu_plugin_dataflow_abi_ok(
            QEMU_PLUGIN_DATAFLOW_VERSION,
            (uint32_t)sizeof(qemu_plugin_dataflow_field),
            (uint32_t)sizeof(qemu_plugin_dataflow_status))) {
        g_refusal = "ABI handshake refused: this plugin and this qemu were "
                    "built against different dataflow versions";
        return;
    }

    g_nregs = qemu_plugin_dataflow_nregs();
    if (g_nregs == 0) {
        g_refusal = "target exposes no TCG globals: nothing to compare";
        return;
    }
    g_nwords = (g_nregs + 63) / 64;
    g_prov_words = qemu_plugin_dataflow_prov_words();
    if (g_prov_words == 0) {
        g_refusal = "qemu reports a zero-word provenance namespace";
        return;
    }

    g_gen_of_reg.assign(g_nregs, (uint8_t)REG_ID_COUNT);
    g_reg_names.assign(g_nregs, nullptr);
    for (unsigned i = 0; i < g_nregs; i++) {
        const char *nm = qemu_plugin_dataflow_reg_name(i, nullptr, nullptr);
        if (!nm) {
            continue;
        }
        g_reg_names[i] = nm;
        uint8_t gen = generic_for_qemu_name(nm);
        if (gen == REG_ID_COUNT) {
            gen = fold_nonarch(nm);
        }
        g_gen_of_reg[i] = gen;
    }
    g_live = true;
}

/* Collect a bitmap into the tracer's vocabulary.  Returns false if the set
 * held a register with no tracer word -- the caller must not score it.
 *
 * A QEMU-INTERNAL temp (nonarch_global) is neither: it is dropped and
 * @nonarch is raised, so the instruction stays scoreable and the reader is
 * still told the drop happened.  See nonarch_global() for why excluding is
 * not the same as inventing a fold. */
bool to_generic(const uint64_t *words, std::vector<uint8_t> &out,
                const char **unmapped_name, bool *nonarch)
{
    bool whole = true;
    out.clear();
    for (unsigned i = 0; i < g_nregs; i++) {
        if (!(words[i / 64] & (1ULL << (i % 64)))) {
            continue;
        }
        uint8_t gen = g_gen_of_reg[i];
        if (gen >= REG_ID_COUNT) {
            if (g_reg_names[i] && nonarch_global(g_reg_names[i])) {
                *nonarch = true;
                continue;
            }
            if (whole && unmapped_name) {
                *unmapped_name = g_reg_names[i];
            }
            whole = false;
            continue;
        }
        out.push_back(gen);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return whole;
}

void diff_names(const std::vector<uint8_t> &ir,
                const std::vector<uint8_t> &tracer,
                const char *tag, GString *sig)
{
    for (uint8_t g : ir) {
        if (!std::binary_search(tracer.begin(), tracer.end(), g)) {
            g_string_append_printf(sig, " ir-%s-extra:%s", tag,
                                   generic_reg_name_or_unknown(g));
        }
    }
    for (uint8_t g : tracer) {
        if (!std::binary_search(ir.begin(), ir.end(), g)) {
            g_string_append_printf(sig, " ir-%s-missing:%s", tag,
                                   generic_reg_name_or_unknown(g));
        }
    }
}

void score_memop_deps(const struct qemu_plugin_tb *tb, size_t idx,
                      const qemu_plugin_insn_info *info,
                      const qemu_plugin_dataflow_status *st,
                      const InsnFieldsScratch &s);

/*
 * Score one instruction's memop claim against QEMU's translation of it, and
 * record whether the 8/8 dataflow capacity was exceeded.
 *
 * The tracer's static claim is decoded here rather than taken from the
 * caller so that the template path is untouched by the presence of the
 * instrument -- the same reason the register arm re-decodes.
 */
bool score_memops(const qemu_plugin_insn_info *info,
                  const qemu_plugin_dataflow_status *st,
                  InsnFieldsScratch &s)
{
    char sig[192];

    if (st->fields_truncated || st->writes_truncated || st->prov_truncated) {
        g_t_fields += st->fields_truncated ? 1 : 0;
        g_t_writes += st->writes_truncated ? 1 : 0;
        g_t_prov   += st->prov_truncated ? 1 : 0;
        tally(&g_trunc_by_mnem, info->mnemonic);
    }

    insn_fields_scratch_reset(&s);
    decode_detail_to_generic(0, info, &s.f, nullptr);

    unsigned tr_ld = s.f.max_dep_loads, tr_st = s.f.max_dep_stores;
    unsigned ir_ld = st->n_mem_reads,   ir_st = st->n_mem_writes;

    if (tr_ld == ir_ld && tr_st == ir_st) {
        g_m_agree++;
        return true;
    }
    /*
     * QEMU emitted fewer memops than the tracer claims AND the instruction
     * calls a helper: the access, if there is one, happens inside the call
     * where no qemu_ld/qemu_st exists to be counted.  Silence there is not
     * evidence, so it is set aside by name instead of scored.
     */
    if (st->n_calls > 0 && ir_ld <= tr_ld && ir_st <= tr_st) {
        g_m_helper_lo++;
        return false;
    }
    g_m_disagree++;
    snprintf(sig, sizeof sig, "%s  ir(%u,%u) tracer(%u,%u)%s",
             info->mnemonic, ir_ld, ir_st, tr_ld, tr_st,
             st->n_calls > 0 ? " [helper]" : "");
    tally(&g_msigs, sig);
    return false;
}

/*
 * One provenance set, translated into the tracer's vocabulary.
 *
 * @regs are generic register ids; @loads is a bitmask of the instruction's
 * load slots whose VALUE this set depends on -- the third region of QEMU's
 * namespace, and the thing that has no Capstone counterpart except through
 * the tracer's own load-data mask bits.  A set naming env state the tracer
 * has no word for raises @field, and one naming a global with no word raises
 * !@whole; neither is scored, because a dropped name is a disagreement that
 * would present as agreement.
 */
struct ProvSet {
    std::vector<uint8_t> regs;
    uint64_t    loads    = 0;
    bool        field    = false;
    bool        whole    = true;
    const char *unmapped = nullptr;
    bool        nonarch  = false;
};

void prov_to_set(const uint64_t *words, unsigned nwords, ProvSet &out)
{
    for (unsigned b = 0; b < nwords * 64; b++) {
        unsigned slot;

        if (!(words[b / 64] & (1ULL << (b % 64)))) {
            continue;
        }
        if (b < g_nregs) {
            uint8_t gen = g_gen_of_reg[b];

            if (gen >= REG_ID_COUNT) {
                if (g_reg_names[b] && nonarch_global(g_reg_names[b])) {
                    out.nonarch = true;
                    continue;
                }
                if (out.whole) {
                    out.unmapped = g_reg_names[b];
                }
                out.whole = false;
                continue;
            }
            out.regs.push_back(gen);
        } else if (qemu_plugin_dataflow_prov_memop(b, &slot)) {
            out.loads |= 1ULL << slot;
        } else {
            /*
             * An env byte range: the vector file, the x87 stack, a status
             * word.  The tracer names those registers, but inverting an env
             * offset back to a register number needs the CPUArchState
             * layout, which a plugin does not have and must not hard-code.
             * So the set is set aside rather than compared minus a name.
             */
            out.field = true;
        }
    }
    std::sort(out.regs.begin(), out.regs.end());
    out.regs.erase(std::unique(out.regs.begin(), out.regs.end()),
                   out.regs.end());
    out.regs.erase(std::remove(out.regs.begin(), out.regs.end(),
                               (uint8_t)REG_PC), out.regs.end());
}

/* The tracer's mask, in the same shape.  Bit layout per
 * champsim_tracer_mnemonics.h: src slots, then load-data slots, then imm. */
void mask_to_set(const InsnFields &f, uint64_t mask, ProvSet &out)
{
    for (unsigned i = 0; i < f.n_src_regs && i < 64; i++) {
        if (mask & (1ULL << i)) {
            out.regs.push_back(f.src_regs[i]);
        }
    }
    for (unsigned k = 0; k < f.max_dep_loads; k++) {
        unsigned bit = f.n_src_regs + k;

        if (bit < 64 && (mask & (1ULL << bit))) {
            out.loads |= 1ULL << k;
        }
    }
    std::sort(out.regs.begin(), out.regs.end());
    out.regs.erase(std::unique(out.regs.begin(), out.regs.end()),
                   out.regs.end());
    out.regs.erase(std::remove(out.regs.begin(), out.regs.end(),
                               (uint8_t)REG_PC), out.regs.end());
}

/* Append every name the two sets do not share.  Empty means they agree. */
void diff_prov(const ProvSet &ir, const ProvSet &tr, const char *tag,
               GString *sig)
{
    diff_names(ir.regs, tr.regs, tag, sig);
    for (unsigned k = 0; k < 64; k++) {
        bool a = ir.loads & (1ULL << k), b = tr.loads & (1ULL << k);

        if (a && !b) {
            g_string_append_printf(sig, " ir-%s-extra:load%u", tag, k);
        } else if (b && !a) {
            g_string_append_printf(sig, " ir-%s-missing:load%u", tag, k);
        }
    }
}

/*
 * CP-M's reader: compare what the EMITTERS said each access depends on
 * against what the Capstone operand walk said.
 *
 * Called only when the two sides already agree on how many accesses there
 * are, because a dependency comparison between differently-shaped access
 * lists is not a comparison of anything.
 */
void score_memop_deps(const struct qemu_plugin_tb *tb, size_t idx,
                      const qemu_plugin_insn_info *info,
                      const qemu_plugin_dataflow_status *st,
                      const InsnFieldsScratch &s)
{
    const InsnFields &f = s.f;
    qemu_plugin_dataflow_memop mo[QEMU_PLUGIN_IRDF_MAX_MEMOPS];
    unsigned n;

    if (f.max_dep_loads == 0 && f.max_dep_stores == 0) {
        return;                                 /* nothing to compare */
    }
    if (f.max_dep_loads > 1 || f.max_dep_stores > 1) {
        g_mq_multi++;
        return;
    }

    for (unsigned i = 0; i < QEMU_PLUGIN_IRDF_MAX_MEMOPS; i++) {
        mo[i].struct_size = sizeof(mo[i]);
    }
    n = qemu_plugin_insn_memops(tb, idx, mo, QEMU_PLUGIN_IRDF_MAX_MEMOPS);
    if (n == QEMU_PLUGIN_DF_INCOMPLETE || n > QEMU_PLUGIN_IRDF_MAX_MEMOPS) {
        g_mq_norecord++;
        return;
    }
    if (n != (unsigned)f.max_dep_loads + (unsigned)f.max_dep_stores) {
        /*
         * The op counts matched but the records do not: an access QEMU
         * emitted has no record.  Counted apart rather than scored, since
         * every pairing below would then be against the wrong access.
         */
        g_mq_mismatch++;
        return;
    }

    std::vector<uint64_t> w(g_prov_words);
    for (unsigned i = 0; i < n; i++) {
        ProvSet ir_addr, tr_addr;
        GString *sig;
        gsize mnem_len;
        bool store = mo[i].is_store != 0;

        if (qemu_plugin_insn_memop_addr_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            g_mq_norecord++;
            return;
        }
        prov_to_set(w.data(), g_prov_words, ir_addr);
        if (ir_addr.field) {
            g_mq_field++;
            continue;
        }
        if (!ir_addr.whole) {
            g_mq_unmapped++;
            tally(&g_unmapped_by_name,
                  ir_addr.unmapped ? ir_addr.unmapped : "?");
            continue;
        }
        if (!f.has_addr_deps) {
            g_mq_nodep++;
            continue;
        }
        mask_to_set(f, store ? f.store_addr_dep_mask[0]
                             : f.load_addr_dep_mask[0], tr_addr);

        sig = g_string_new(info->mnemonic);
        mnem_len = sig->len;
        diff_prov(ir_addr, tr_addr, store ? "staddr" : "ldaddr", sig);
        if (sig->len == mnem_len) {
            g_ma_agree++;
            if (RefTally *rt = reftally_for(g_cur_refiner)) rt->ma_agree++;
        } else {
            g_ma_disagree++;
            if (RefTally *rt = reftally_for(g_cur_refiner)) rt->ma_disagree++;
            tally(&g_masigs, sig->str);
        }
        g_string_free(sig, TRUE);

        if (!store) {
            continue;
        }

        /* The stored VALUE.  The tracer only claims one when a refiner
         * published a dep block; without one there is nothing to compare. */
        if (qemu_plugin_insn_memop_data_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            g_mq_norecord++;
            continue;
        }
        ProvSet ir_data, tr_data;
        prov_to_set(w.data(), g_prov_words, ir_data);
        if (ir_data.field) {
            g_mq_field++;
            continue;
        }
        if (!ir_data.whole) {
            g_mq_unmapped++;
            continue;
        }
        if (!f.has_reg_deps) {
            g_mq_nodep++;
            continue;
        }
        if (st->n_calls > 0) {
            /*
             * The value may have been produced inside the call, where no op
             * names it.  x86 fnstcw is the case in point: the tracer says
             * the stored value comes from the FPU control word and it does,
             * but the IR never saw it because a helper wrote it.  Silence
             * from a walk that did not look is not a disagreement.
             */
            g_mq_helper++;
            continue;
        }
        mask_to_set(f, f.store_data_dep_mask[0], tr_data);
        sig = g_string_new(info->mnemonic);
        mnem_len = sig->len;
        diff_prov(ir_data, tr_data, "stdata", sig);
        if (sig->len == mnem_len) {
            g_md_agree++;
            if (RefTally *rt = reftally_for(g_cur_refiner)) rt->md_agree++;
        } else {
            g_md_disagree++;
            if (RefTally *rt = reftally_for(g_cur_refiner)) rt->md_disagree++;
            tally(&g_mdsigs, sig->str);
        }
        g_string_free(sig, TRUE);
    }

    /*
     * The load-to-use edge, as PRESENCE rather than per-register.
     *
     * "Does any destination of this instruction depend on the value the load
     * returned, rather than on the registers that computed its address?"
     * QEMU can only answer that because the emitter said which temp was the
     * data; before CP-M the answer was structurally unavailable, since the
     * loaded value's provenance WAS the address registers.
     */
    if (f.max_dep_loads == 1 && f.n_dst_regs > 0 && f.has_reg_deps) {
        bool tr_use = false, ir_use = false;
        unsigned nw;

        if (st->n_calls > 0) {
            /*
             * A helper can consume the loaded value and write the
             * destination itself -- x86 `divq (%rbx)` writes rax and rdx
             * from inside helper_divq, so the walk sees no register write
             * to carry a provenance at all.  Not evidence either way.
             */
            g_mq_helper++;
            return;
        }

        for (unsigned d = 0; d < f.n_dst_regs; d++) {
            unsigned bit = f.n_src_regs;

            if (bit < 64 && (f.dst_dep_mask[d] & (1ULL << bit))) {
                tr_use = true;
            }
        }
        nw = qemu_plugin_insn_reg_writes(tb, idx, w.data(),
                                         (unsigned)w.size());
        if (nw != QEMU_PLUGIN_DF_INCOMPLETE && nw <= w.size()) {
            std::vector<uint64_t> wr(w.begin(), w.begin() + nw);
            std::vector<uint64_t> pw(g_prov_words);

            for (unsigned r = 0; r < g_nregs && !ir_use; r++) {
                if (!(wr[r / 64] & (1ULL << (r % 64)))) {
                    continue;
                }
                if (qemu_plugin_insn_write_prov(tb, idx, r, pw.data(),
                                                g_prov_words) != g_prov_words) {
                    continue;
                }
                ProvSet p;
                prov_to_set(pw.data(), g_prov_words, p);
                if (p.loads) {
                    ir_use = true;
                }
            }
            /*
             * A destination the TCG-global namespace does not name is still
             * a destination: `movdqa (%rsi),%xmm0` writes the vector file,
             * which QEMU reaches by env offset and reports as a FIELD.
             * Scanning only the globals reported ir-load-use=0 for every
             * vector load and scored the tracer wrong for saying otherwise
             * -- a defect in this reader, not a disagreement about the
             * machine, and the kind that would have been quoted as one.
             */
            unsigned nf = qemu_plugin_insn_fields(tb, idx, nullptr, 0);
            if (nf != QEMU_PLUGIN_DF_INCOMPLETE && nf > 0 &&
                nf <= QEMU_PLUGIN_IRDF_MAX_FIELDS && !ir_use) {
                for (unsigned fi = 0; fi < nf && !ir_use; fi++) {
                    ProvSet p;

                    if (qemu_plugin_insn_field_prov(tb, idx, fi, pw.data(),
                                                    g_prov_words)
                        != g_prov_words) {
                        continue;
                    }
                    prov_to_set(pw.data(), g_prov_words, p);
                    if (p.loads) {
                        ir_use = true;
                    }
                }
            }
            if (ir_use == tr_use) {
                g_mu_agree++;
                if (RefTally *rt = reftally_for(g_cur_refiner)) rt->mu_agree++;
            } else {
                char sig[192];

                g_mu_disagree++;
                if (RefTally *rt = reftally_for(g_cur_refiner)) rt->mu_disagree++;
                snprintf(sig, sizeof sig, "%s  ir-load-use=%d tracer=%d",
                         info->mnemonic, (int)ir_use, (int)tr_use);
                tally(&g_musigs, sig);
            }
        }
    }
}

void dump_tally(GString *report, GHashTable *t, const char *heading)
{
    GList *keys;

    if (!t || g_hash_table_size(t) == 0) {
        return;
    }
    g_string_append_printf(report, "\n%s:\n", heading);
    keys = g_list_sort(g_hash_table_get_keys(t), (GCompareFunc)g_strcmp0);
    for (GList *l = keys; l; l = l->next) {
        gpointer v = g_hash_table_lookup(t, l->data);
        g_string_append_printf(report, "  %8" PRIu64 "  %s\n",
                               (uint64_t)GPOINTER_TO_SIZE(v),
                               (const char *)l->data);
    }
    g_list_free(keys);
}

/*
 * The CP-H ceiling arm.  See the counter block for what the number is for.
 *
 * Each class gets its own scoreboard and each translated instruction is given
 * an inline add into the one its model lands in, so the totals below are
 * EXECUTIONS and not translations.  The scoreboards are created lazily and a
 * failure to create them is recorded rather than silently producing a
 * dynamic column of zeroes that reads like "nothing was approximate".
 */
void score_helper_model(const struct qemu_plugin_tb *tb, size_t idx,
                        const qemu_plugin_dataflow_status *st)
{
    unsigned m = st->helper_model;

    if (m > 2) {
        /*
         * A model this build does not know.  Charging it to one of the three
         * would put an unknown answer inside a published fraction.
         */
        g_h_sb_failed = true;
        return;
    }
    g_h_static[m]++;
    g_h_static_unknown += st->n_helper_unknown;
    g_h_static_unbounded += st->n_helper_unbounded;
    g_h_static_calls += st->n_calls > 0 ? 1 : 0;

    if (g_h_sb_failed) {
        return;
    }
    if (g_h_sb[0] == nullptr) {
        for (int i = 0; i < 3; i++) {
            g_h_sb[i] = qemu_plugin_scoreboard_new(sizeof(uint64_t));
            if (g_h_sb[i] == nullptr) {
                g_h_sb_failed = true;
                return;
            }
        }
    }
    struct qemu_plugin_insn *insn =
        qemu_plugin_tb_get_insn(tb, idx);
    if (insn == nullptr) {
        g_h_sb_failed = true;
        return;
    }
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        insn, QEMU_PLUGIN_INLINE_ADD_U64,
        qemu_plugin_scoreboard_u64(g_h_sb[m]), 1);
}

/*
 * One instruction's contribution to the per-refiner verdict.
 *
 * Two decodes of the same encoding, differing only in whether the row's
 * refiner ran, and both taken here rather than borrowed from the template
 * path -- the same reason the register and memop arms re-decode: the presence
 * of the instrument must not change what the tracer builds.
 */
void score_refiner(const qemu_plugin_insn_info *info,
                   const qemu_plugin_dataflow_status *st)
{
    const char *name = g_cur_refiner;

    if (!name) {
        return;
    }
    RefTally *t = reftally_for(name);
    if (!t) {
        return;
    }
    t->rows++;
    if (st && st->helper_model < 3) {
        t->h_class[st->helper_model]++;
    }

    InsnFieldsScratch on_s, off_s;
    insn_fields_scratch_reset(&on_s);
    decode_detail_to_generic(0, info, &on_s.f, nullptr);
    dep_refine_set_suppressed(true);
    insn_fields_scratch_reset(&off_s);
    decode_detail_to_generic(0, info, &off_s.f, nullptr);
    dep_refine_set_suppressed(false);

    const InsnFields &on = on_s.f;
    const InsnFields &off = off_s.f;

    if (on.max_dep_loads != off.max_dep_loads ||
        on.max_dep_stores != off.max_dep_stores ||
        on.has_addr_deps != off.has_addr_deps) {
        t->reshapes++;
        char sig[128];
        g_snprintf(sig, sizeof(sig),
                   "%-34s ndst=%u nsrc=%u nload=%u nstore=%u",
                   name, off.n_dst_regs, off.n_src_regs,
                   off.max_dep_loads, off.max_dep_stores);
        tally(&g_refshape, sig);
        return;
    }

    /*
     * Same shape.  The default a consumer applies to a row with no HAS_REG
     * block is all-inputs on every destination and every stored value, so
     * that is what the refiner's output is held against.
     */
    {
        char sig[128];
        g_snprintf(sig, sizeof(sig),
                   "%-34s ndst=%u nsrc=%u nload=%u nstore=%u",
                   name, off.n_dst_regs, off.n_src_regs,
                   off.max_dep_loads, off.max_dep_stores);
        tally(&g_refshape, sig);
    }

    const uint64_t dflt = all_inputs_of(&on);
    bool narrower = false, wider = false;

    for (uint8_t d = 0; d < on.n_dst_regs; d++) {
        uint64_t m = on.dst_dep_mask[d];
        if (m & ~dflt) {
            wider = true;
        }
        if ((m & dflt) != dflt) {
            narrower = true;
        }
    }
    for (uint8_t k = 0; k < on.max_dep_stores && k < MAX_STORES; k++) {
        uint64_t m = on.store_data_dep_mask[k];
        if (m & ~dflt) {
            wider = true;
        }
        if ((m & dflt) != dflt) {
            narrower = true;
        }
    }
    /*
     * A row that publishes no block at all is INERT for the same reason a row
     * publishing the default is: the consumer reads the same dependency set
     * either way.  A refiner whose shape precondition did not hold takes
     * this path, which is why the shape tally below is read beside it.
     */
    if (!on.has_reg_deps) {
        /*
         * Counted apart from INERT because the two have different costs.  A
         * refiner that bailed published NO block, so the row spends no bytes
         * to reach the reader's default; a refiner that published the
         * default spent bytes to restate it.  Only the second is waste, and
         * conflating them would let a harmless bail-out be quoted as one.
         */
        t->silent++;
        return;
    }
    if (wider) {
        t->widens++;
    } else if (narrower) {
        t->narrows++;
    } else {
        t->inert++;
    }
}

} /* namespace */

void irdf_note_insn(const struct qemu_plugin_tb *tb, size_t idx,
                    const qemu_plugin_insn_info *info)
{
    if (!g_on || !info || !info->mnemonic[0]) {
        return;
    }

    std::lock_guard<std::mutex> lk(g_lock);
    if (!g_tried) {
        irdf_init_locked();
    }
    if (!g_live) {
        return;
    }

    /*
     * Ask what was NOT seen before asking what was.
     *
     * QEMU_PLUGIN_DF_INCOMPLETE covers only the extraction running out of
     * room.  It does NOT cover a helper: an instruction whose work happens
     * inside helper_divq or the SSE helpers yields a set that is complete
     * for the TCG globals it touched and silent about everything the helper
     * did, because that state is not a TCG global at all.  Scoring such an
     * instruction reports "the tracer claims reads the IR does not have",
     * which is true and useless -- the IR never looked.  n_calls is how the
     * status struct says so, and it is the same distinction the offline
     * comparison already had to be taught: a refusal is not a disagreement.
     */
    qemu_plugin_dataflow_status st;
    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        g_n_declined++;
        g_m_nostatus++;
        return;
    }

    /*
     * The refiner attribution is established BEFORE the memop arm, because
     * that arm's verdicts are among the things being attributed: which
     * refiner produced the store-data claim QEMU's emitters are being held
     * against is the per-refiner half of the retirement question.
     */
    g_cur_refiner = dep_refine_name_for(info);

    /* The memop arm runs BEFORE the register arm's refusals, because none of
     * them applies to it -- see the counter block. */
    InsnFieldsScratch mem_s;
    if (score_memops(info, &st, mem_s)) {
        score_memop_deps(tb, idx, info, &st, mem_s);
    }

    /*
     * The CP-H arm, likewise before the refusals: a helper is exactly what
     * this arm is here to measure, so declining on one would leave the number
     * defined over the instructions that did not need it.
     */
    score_helper_model(tb, idx, &st);
    score_refiner(info, &st);

    if (st.n_calls > 0) {
        g_n_helper++;
        return;
    }

    /*
     * The third refusal, and the one specific to this target.
     *
     * x86's vector file, x87 stack, MXCSR and segment SELECTORS are not TCG
     * globals; QEMU reaches them by load and store at an offset into
     * CPUArchState, and the register bitmap is silent about them by
     * construction.  A `pxor %xmm0,%xmm0` therefore comes back with an empty
     * read set even though the extraction recorded the accesses perfectly
     * well -- as FIELDS, in a namespace this instrument cannot yet spell,
     * because inverting an env offset back to a register number needs the
     * CPUArchState layout, which a plugin does not have and must not
     * hard-code (that assumption is the exact failure the dataflow header
     * was designed around).
     *
     * So: if the instruction touched any field, decline it.  Scoring it
     * would report the tracer's xmm dependencies as things "the IR does not
     * have", when the IR has them and the gap is in the reader.
     */
    qemu_plugin_dataflow_field fields[1];
    fields[0].struct_size = sizeof(fields[0]);
    if (qemu_plugin_insn_fields(tb, idx, fields, 1) > 0) {
        g_n_fields++;
        return;
    }

    std::vector<uint64_t> rd(g_nwords), wr(g_nwords);
    unsigned nr = qemu_plugin_insn_reg_reads(tb, idx, rd.data(), g_nwords);
    unsigned nw = qemu_plugin_insn_reg_writes(tb, idx, wr.data(), g_nwords);

    /*
     * A refusal is not a disagreement.  The accessors hand back nothing at
     * all when the extraction could not represent the instruction -- a
     * helper it cannot see inside, most often -- and counting that as a
     * decoder mismatch is exactly the overstatement this arc already had to
     * correct once, in the offline comparison.
     */
    if (nr == QEMU_PLUGIN_DF_INCOMPLETE || nw == QEMU_PLUGIN_DF_INCOMPLETE ||
        nr > g_nwords || nw > g_nwords) {
        g_n_declined++;
        return;
    }

    std::vector<uint8_t> ir_r, ir_w;
    const char *unmapped = nullptr;
    bool nonarch = false;
    bool whole = to_generic(rd.data(), ir_r, &unmapped, &nonarch);
    whole &= to_generic(wr.data(), ir_w, &unmapped, &nonarch);
    if (!whole) {
        g_n_unmapped++;
        tally(&g_unmapped_by_name, unmapped ? unmapped : "?");
        return;
    }
    if (nonarch) {
        g_n_nonarch++;
    }

    /* The tracer's own answer for the same encoding, decoded here so the
     * template path is untouched by the presence of the instrument. */
    InsnFieldsScratch s;
    insn_fields_scratch_reset(&s);
    decode_detail_to_generic(0, info, &s.f, nullptr);

    std::vector<uint8_t> tr_r(s.f.src_regs, s.f.src_regs + s.f.n_src_regs);
    std::vector<uint8_t> tr_w(s.f.dst_regs, s.f.dst_regs + s.f.n_dst_regs);
    std::sort(tr_r.begin(), tr_r.end());
    std::sort(tr_w.begin(), tr_w.end());
    tr_r.erase(std::unique(tr_r.begin(), tr_r.end()), tr_r.end());
    tr_w.erase(std::unique(tr_w.begin(), tr_w.end()), tr_w.end());

    /*
     * The program counter is dropped from both sides, for the reason
     * isaxcheck drops it: whether QEMU materialises it is a property of
     * where the TB ended, not of the instruction.
     */
    auto drop_ip = [](std::vector<uint8_t> &v) {
        v.erase(std::remove(v.begin(), v.end(), (uint8_t)REG_PC), v.end());
    };
    drop_ip(ir_r); drop_ip(ir_w); drop_ip(tr_r); drop_ip(tr_w);

    GString *sig = g_string_new(info->mnemonic);
    gsize mnem_len = sig->len;
    diff_names(ir_r, tr_r, "rd", sig);
    diff_names(ir_w, tr_w, "wr", sig);
    if (sig->len == mnem_len) {
        g_n_agree++;
    } else {
        g_n_disagree++;
        tally(&g_sigs, sig->str);
    }
    g_string_free(sig, TRUE);
}

void irdf_enable(bool on)
{
    std::lock_guard<std::mutex> lk(g_lock);
    g_on = on;
}

/*
 * A percentage that cannot lie by rounding.  "<0.01%" for a non-empty class
 * that rounds to zero, ">99.99%" for a class that is not the whole
 * population but rounds to a hundred.
 */
static void irdf_fmt_pct(char *buf, size_t n, uint64_t part, uint64_t tot)
{
    double p;

    if (tot == 0) {
        snprintf(buf, n, "%s", "  n/a ");
        return;
    }
    p = 100.0 * (double)part / (double)tot;
    if (part != 0 && p < 0.005) {
        snprintf(buf, n, "%s", "<0.01%");
    } else if (part != tot && p > 99.995) {
        snprintf(buf, n, "%s", ">99.99%");
    } else {
        snprintf(buf, n, "%6.2f%%", p);
    }
}

void irdf_report(GString *report)
{
    if (!report || !g_on) {
        return;
    }
    std::lock_guard<std::mutex> lk(g_lock);

    g_string_append_printf(report, "\n=== irdf: QEMU IR dataflow vs the tracer's decode ===\n");
    g_string_append_printf(report,
            "WHAT THIS NUMBER IS: an INTERNAL-CONSISTENCY check, not a\n"
            "reference.  Both sides derive from this tree -- QEMU's own\n"
            "translation of the encoding, and the tracer's Capstone decode of\n"
            "the same bytes -- so agreement is evidence that the two accounts\n"
            "of one machine still match, and a disagreement convicts one of\n"
            "them without saying which.  It does not belong in any coverage\n"
            "total that sums independent references.\n");
    if (!g_tried) {
        g_string_append_printf(report, "irdf=1 but no instruction was ever translated\n");
        return;
    }
    if (!g_live) {
        g_string_append_printf(report, "DISABLED: %s\n", g_refusal);
        return;
    }

    g_string_append_printf(report, "namespace: %u TCG globals, %u mapped to a tracer register\n",
            g_nregs,
            (unsigned)std::count_if(g_gen_of_reg.begin(), g_gen_of_reg.end(),
                                    [](uint8_t g) { return g < REG_ID_COUNT; }));
    for (unsigned i = 0; i < g_nregs; i++) {
        g_string_append_printf(report, "  %-16s %s\n",
                g_reg_names[i] ? g_reg_names[i] : "(unnamed)",
                g_gen_of_reg[i] < REG_ID_COUNT
                    ? generic_reg_name_or_unknown(g_gen_of_reg[i])
                    : "(no tracer word)");
    }

    g_string_append_printf(report, "\nscored:   %" PRIu64 " agree, %" PRIu64 " disagree\n",
            g_n_agree, g_n_disagree);
    g_string_append_printf(report,
            "declined: %" PRIu64 " helper (work inside a call the walk cannot "
            "see into)\n"
            "          %" PRIu64 " field  (touched CPU state the TCG-GLOBAL "
            "namespace omits -- vector, x87, selectors.  That is THIS WALK's "
            "ceiling, not QEMU's: qemu_plugin_insn_fields() reported the "
            "access with an env_offset and a size and this instrument "
            "discarded it)\n"
            "          %" PRIu64 " incomplete (extraction ran out of room)\n"
            "          -- NONE of these is a disagreement\n",
            g_n_helper, g_n_fields, g_n_declined);
    g_string_append_printf(report, "unmapped: %" PRIu64 " (touched a global with no tracer word; "
               "reported, never scored)\n", g_n_unmapped);
    g_string_append_printf(report,
            "nonarch:  %" PRIu64 " of the scored instructions touched a "
            "QEMU-INTERNAL temp that is not architectural state (the "
            "load-exclusive monitor, the MIPS delay-slot branch machinery); "
            "that name was dropped from the IR side and the instruction was "
            "still scored\n", g_n_nonarch);

    dump_tally(report, g_unmapped_by_name,
               "globals the tracer has no word for");
    dump_tally(report, g_sigs, "disagreement signatures");

    g_string_append_printf(report,
            "\n--- memops: QEMU's translation vs the tracer's static claim ---\n"
            "scored:   %" PRIu64 " agree, %" PRIu64 " disagree\n"
            "declined: %" PRIu64 " helper-low (ir has fewer AND the insn calls "
            "a helper: an access inside the call emits no qemu_ld/qemu_st, so "
            "silence is not evidence)\n"
            "          %" PRIu64 " no status\n",
            g_m_agree, g_m_disagree, g_m_helper_lo, g_m_nostatus);
    dump_tally(report, g_msigs, "memop disagreement signatures");

    g_string_append_printf(report,
            "\n--- memop DEPENDENCIES: the emitters vs the operand walk ---\n"
            "WHAT IS COMPARED: for each access, which registers QEMU's own\n"
            "emitter said computed its ADDRESS and produced its DATA, against\n"
            "the masks the tracer built from Capstone's MEM operand and its\n"
            ".dep_refine.  These are two independent derivations of one fact,\n"
            "which is what makes the comparison worth taking -- and it is\n"
            "still an internal-consistency check, not a reference.\n"
            "address:   %" PRIu64 " agree, %" PRIu64 " disagree\n"
            "store data:%" PRIu64 " agree, %" PRIu64 " disagree\n"
            "load-use:  %" PRIu64 " agree, %" PRIu64 " disagree  (does a "
            "destination depend on the VALUE loaded rather than on the "
            "address registers -- the edge that did not exist on the QEMU "
            "side until the emitters stated it)\n"
            "not scored: %" PRIu64 " several accesses of a kind (slot "
            "ordering between the two lists is unproven, never assumed)\n"
            "            %" PRIu64 " qemu withheld whole records\n"
            "            %" PRIu64 " records disagreed with the op counts\n"
            "            %" PRIu64 " a provenance named env state the tracer "
            "cannot spell (vector file, x87, status words)\n"
            "            %" PRIu64 " a global with no tracer word\n"
            "            %" PRIu64 " the tracer published no dep block to "
            "compare (no .dep_refine on the row)\n"
            "            %" PRIu64 " the value could have been produced or "
            "consumed inside a helper call, where no op names it -- silence "
            "from a walk that did not look is not a disagreement\n",
            g_ma_agree, g_ma_disagree, g_md_agree, g_md_disagree,
            g_mu_agree, g_mu_disagree, g_mq_multi, g_mq_norecord,
            g_mq_mismatch, g_mq_field, g_mq_unmapped, g_mq_nodep,
            g_mq_helper);
    dump_tally(report, g_masigs, "address-dependency disagreements");
    dump_tally(report, g_mdsigs, "store-data-dependency disagreements");
    dump_tally(report, g_musigs, "load-to-use disagreements");

    g_string_append_printf(report,
            "\ntruncation (INSN_DF_MAX_FIELDS=8 / INSN_DF_MAX_WRITES=8): "
            "%" PRIu64 " fields, %" PRIu64 " writes, %" PRIu64 " prov; "
            "%u distinct opcodes\n"
            "  -- this bounds the REGISTER dataflow API only: memop recording "
            "runs off the runtime memory callback and is not gated by it.\n",
            g_t_fields, g_t_writes, g_t_prov,
            g_trunc_by_mnem ? g_hash_table_size(g_trunc_by_mnem) : 0);
    dump_tally(report, g_trunc_by_mnem, "opcodes that overflowed the 8/8 limits");

    /* --- the CP-H ceiling --- */
    uint64_t dyn[3] = {0, 0, 0};
    uint64_t dyn_tot = 0, st_tot = 0;

    for (int i = 0; i < 3; i++) {
        if (g_h_sb[i]) {
            dyn[i] = qemu_plugin_u64_sum(qemu_plugin_scoreboard_u64(g_h_sb[i]));
        }
        dyn_tot += dyn[i];
        st_tot += g_h_static[i];
    }

    /* --- the per-refiner verdict --- */
    g_string_append_printf(report,
            "\n--- .dep_refine, per refiner: what each row states over the "
            "format's own default ---\n"
            "INERT    the refiner published exactly what a consumer assumes "
            "when a row carries NO dependency block: all-inputs on every "
            "destination and every stored value, same memop shape.  Such a "
            "row costs bytes and states nothing.\n"
            "NARROWS  same shape, at least one mask a proper SUBSET of "
            "all-inputs -- an edge the default does not have.\n"
            "RESHAPES the refiner changed the memop shape (added a push's "
            "implicit stores, removed an address-compute's phantom load).  "
            "The default cannot express a shape it was never given.\n"
            "WIDENS   a mask carrying a bit all-inputs does not.  Not a "
            "refinement of anything; a zero here is measured, not assumed.\n"
            "The h-EXACT/APPROX/OPAQUE columns are the CP-H model of the SAME "
            "instructions -- what the emitter-stated model could say if the "
            "row went away.\n"
            "SILENT   the refiner bailed and published NO block.  Reaches the "
            "same default, but spends no bytes doing it -- counted apart from "
            "INERT because only INERT is waste.\n"
            "%-30s %8s %8s %8s %8s %8s %7s | %8s %7s %8s\n",
            "refiner", "rows", "inert", "silent", "narrows", "reshapes",
            "widens", "h-EXACT", "h-APPRX", "h-OPAQUE");
    if (g_reftally) {
        GList *keys = g_hash_table_get_keys(g_reftally);
        keys = g_list_sort(keys, (GCompareFunc)g_strcmp0);
        for (GList *l = keys; l; l = l->next) {
            const char *k = (const char *)l->data;
            RefTally *t = (RefTally *)g_hash_table_lookup(g_reftally, k);
            g_string_append_printf(report,
                    "%-30s %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64
                    " %8" PRIu64 " %7" PRIu64 " | %8" PRIu64 " %7" PRIu64
                    " %8" PRIu64 "\n",
                    k, t->rows, t->inert, t->silent, t->narrows, t->reshapes,
                    t->widens, t->h_class[0], t->h_class[1], t->h_class[2]);
        }
        g_string_append_printf(report,
                "\nand the memop-dependency verdicts of the same rows, "
                "against what QEMU's emitters stated:\n"
                "%-34s %11s %11s %11s\n",
                "refiner", "addr a/d", "sdata a/d", "load-use a/d");
        for (GList *l = keys; l; l = l->next) {
            const char *k = (const char *)l->data;
            RefTally *t = (RefTally *)g_hash_table_lookup(g_reftally, k);
            g_string_append_printf(report,
                    "%-34s %5" PRIu64 "/%-5" PRIu64 " %5" PRIu64 "/%-5" PRIu64
                    " %5" PRIu64 "/%-5" PRIu64 "\n",
                    k, t->ma_agree, t->ma_disagree, t->md_agree,
                    t->md_disagree, t->mu_agree, t->mu_disagree);
        }
        g_list_free(keys);
    } else {
        g_string_append_printf(report, "  (no row carried a refiner)\n");
    }
    dump_tally(report, g_refshape,
               "the shape the operand walk handed each refiner");

    g_string_append_printf(report,
            "\n--- CP-H: how much of the dependency model the EMITTERS state ---\n"
            "This is the CEILING on retiring a decoder-derived dependency\n"
            "classifier.  EXACT means every operand of every helper the\n"
            "instruction called was named by the emitter that called it, with\n"
            "its extent and its direction.  APPROX means the operand SET is\n"
            "stated but at least one operand's DIRECTION is not, so it is\n"
            "recorded as read-and-written -- sound in the pessimistic\n"
            "direction, and NOT exact.  OPAQUE means the operand set was not\n"
            "stated at all.\n");
    if (st_tot == 0) {
        g_string_append_printf(report, "no instruction was scored\n");
        return;
    }
    static const char *const kName[3] = {"EXACT ", "APPROX", "OPAQUE"};
    /*
     * A non-empty class must never print as 0.00%, and a class that is not
     * the whole population must never print as 100.00%.  Two decimal places
     * rounded x86_64's 610 opaque executions -- out of 68 million -- to
     * "0.00%" and its EXACT column to "100.00%", which reads as a class that
     * is empty when it is not.  That is this project's named dominant defect
     * shape appearing in the report of the very measurement meant to be
     * honest about what the model cannot describe.
     */
    g_string_append_printf(report,
            "                 translated            executed\n");
    for (int i = 0; i < 3; i++) {
        char sp[16], dp[16];

        irdf_fmt_pct(sp, sizeof(sp), g_h_static[i], st_tot);
        irdf_fmt_pct(dp, sizeof(dp), dyn[i], dyn_tot);
        g_string_append_printf(report,
                "  %s  %12" PRIu64 " %7s  %14" PRIu64 " %7s\n",
                kName[i], g_h_static[i], sp, dyn[i], dp);
    }
    g_string_append_printf(report,
            "  total   %12" PRIu64 "          %14" PRIu64 "\n", st_tot, dyn_tot);
    g_string_append_printf(report,
            "  %" PRIu64 " of the translated instructions call a helper at all\n"
            "  %" PRIu64 " (helper, pointer argument) pairs have no direction "
            "written down; each is an operand recorded as read-and-written "
            "because nothing states which\n"
            "  %" PRIu64 " helper calls have no bounded footprint at all -- "
            "handed the whole CPU state pointer, or not declared free of "
            "global reads and writes, in which case QEMU's own register "
            "allocator treats them as touching every register while the op "
            "list names none of them, so the extracted sets are SHORT and not "
            "merely coarse\n",
            g_h_static_calls, g_h_static_unknown, g_h_static_unbounded);
    if (g_h_sb_failed) {
        g_string_append_printf(report,
                "  WARNING: the execution-weighted column is INCOMPLETE -- a "
                "scoreboard or an instruction handle was refused, so at least "
                "one instruction was counted in the translated column and not "
                "in the executed one.  Do not quote the executed percentages.\n");
    } else if (dyn_tot == 0) {
        g_string_append_printf(report,
                "  WARNING: nothing was counted as executed.  A translated "
                "instruction that never runs is ordinary; a whole run of them "
                "is an instrument that did not fire, and the executed column "
                "must not be read as a measurement.\n");
    }
}
