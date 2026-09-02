/*
 * The wire's dependency families, from the emitters that stated them.
 *
 * Author: Maccoy Merrell
 *
 * See champsim_tracer_qdep.h for what this replaces, what the zero-register
 * ruling decided, why the HAS_REG flag being shared bounds both halves of
 * the register block, and which population of the DESTINATION family is
 * QEMU's -- the rest keeps the refiner's mask and is counted by cause.
 */

#include <algorithm>
#include <atomic>
#include <cstring>
#include <array>
#include <mutex>
#include <set>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_qdep.h"
#include "champsim_tracer_src_survivors.h"

/* The dataflow header carries no linkage guard of its own -- neither does
 * qemu-plugin.h, which champsim_tracer.h wraps the same way.  Without this
 * the plugin asks the loader for a mangled name and fails to dlopen, which
 * is exactly what happened on the first build of this file and exactly what
 * the four-target dlopen smoke exists to catch. */
extern "C" {
#include <qemu-plugin-dataflow.h>
}

namespace {

/*
 * Room for one instruction's accesses.  A form that needs more is REFUSED
 * and counted, never truncated: a partial access list is the shape most
 * likely to pass for a whole one, and a mask built from a partial list is
 * short in exactly the direction that costs a consumer correctness.
 */
constexpr unsigned kMaxMemops = 64;
/*
 * Env-field records per instruction.  Comfortably above QEMU's own
 * INSN_DF_MAX_FIELDS so the cap that bites is the extractor's, which SAYS it
 * overflowed, rather than this one, which would only see a smaller number.
 */
/*
 * Raised from 64 to 128 in step with INSN_DF_MAX_FIELDS' rise to 64 at PASS
 * 49; the inequality between the two is the whole point of the bound.
 */
constexpr unsigned kMaxFields = 128;
/*
 * Destinations the encoding names that the emulator discards
 * (qemu_plugin_insn_discards()).  QEMU's own cap is four; eight leaves the
 * refusal above reachable if that ever grows, which is the direction a
 * short destination LIST must fail in.
 */
constexpr unsigned kMaxDiscards = 8;
/*
 * Sources the encoding names that have neither a global nor an env range
 * (qemu_plugin_insn_named_reads()).  QEMU's own cap is four; eight leaves
 * the refusal reachable if that grows, for the same reason kMaxDiscards is
 * wider than its own -- a source LIST must fail in the direction that says
 * so rather than silently reading a short one.
 */
constexpr unsigned kMaxNamedReads = 8;

std::atomic<bool>     g_tried{false};
bool                  g_live = false;
const char           *g_refusal = nullptr;
unsigned              g_nregs = 0;
unsigned              g_prov_words = 0;
std::vector<uint8_t>  g_gen_of_reg;      /* TCG global index -> GenericRegId */
/*
 * THE LOWERED-REGISTER MAP -- the two facts the lazy-flag interpretation
 * needs, both read off QEMU once at init (#265/#184).
 *
 * @g_reg_is_selector: QEMU declared this global the SELECTOR of a lowered
 * register's representation (insn_dataflow_declare_repr_selector).  x86's
 * cc_op is the one on file: it says WHICH function computes EFLAGS from
 * cc_dst/cc_src/cc_src2 and holds no part of the value.  The target states
 * it because nothing downstream can tell -- the write is a constant store,
 * and so is `mov $5,%rax`'s.
 *
 * @g_gen_nglobals: how many globals fold to each generic register.  Two or
 * more means the register is LOWERED: several globals stand for one
 * architectural name, and a write from one of them to another moves the
 * value between representations rather than changing it.  One means the
 * register has a single home, where a write naming itself is an ACCUMULATE
 * (#228) and must keep its edge.  The count is what separates
 * `jl` (cc_src <- cc_src) from `add %rax,%rax` (rax <- rax), and it is a
 * property of QEMU's lowering, not of any mnemonic.
 */
std::vector<uint8_t>  g_reg_is_selector;
std::array<uint16_t, REG_ID_COUNT> g_gen_nglobals{};

/* Census.  Indexed by QDepState; every extracted instruction lands in
 * exactly one bucket per family, so each column sums to the instructions
 * seen.  Two arrays because the two families refuse for different reasons on
 * different rows and one merged column could not say which. */
std::atomic<uint64_t> g_state[QDEP_STATE_COUNT];
std::atomic<uint64_t> g_dstate[QDEP_STATE_COUNT];
/* The destination family's own column.  Third array for the same reason
 * there are two: a row refused here is refused for reasons the other two
 * cannot reach -- a wire destination QEMU named only as a CPUArchState byte
 * range -- and a merged column could not say which family that was. */
std::atomic<uint64_t> g_wstate[QDEP_STATE_COUNT];

/*
 * THE CAPSTONE SHADOW IS GONE, and that is a deletion rather than an
 * omission.  Six counters and two signature tallies used to score the masks
 * the operand walk would have published against the ones QEMU's emitters
 * state, on every row the wire takes from QEMU.  They fed nothing and were
 * kept as a comparison arm -- which is exactly the shape J7 forbids on a
 * path whose source has become QEMU, because a value still read is a value
 * still relied on and the next question that needs an answer takes it.  The
 * one-time A/B that retired them is in this wave's evidence, not in the
 * running plugin.
 *
 * What survives is QEMU-side and not comparative: a name QEMU's provenance
 * gave that this file has no generic word for is a REFUSAL, and a refusal
 * nobody can name is a refusal nobody can act on.
 */
GMutex g_tally_lock;
GHashTable *g_unmapped_name = nullptr;   /* qemu global name -> count */
GHashTable *g_monitor_name  = nullptr;   /* reservation-monitor global -> count */
/*
 * A TCG global QEMU stated a WRITE to that this file has no generic word
 * for.  Not a refusal: a name the tracer's vocabulary does not contain
 * cannot equal any `dst_regs[d]`, so it is never the slot a mask would be
 * written for.  Tallied because "it cannot be a destination" is a claim
 * about a population, and a population nobody counted is a population
 * nobody checked.
 */
GHashTable *g_dst_unmapped_name = nullptr;

/*
 * THE SOURCE-SIDE MEMBERSHIP CENSUS (the unmeasured half).
 *
 * The destination list has been scored against QEMU's writes since #232.
 * The SOURCE list never was, and "not measured" was being carried as though
 * it were "measured and fine".  These count, per published `src_regs[i]`,
 * whether QEMU stated a read that justifies it.
 *
 * @g_src_justified / @g_src_unjustified partition the published entries of
 * every instruction whose read list QEMU gave us.  @g_src_nostate counts the
 * entries of instructions where it did not, which is a THIRD outcome and not
 * a failure of the register: folding those into unjustified would blame the
 * wire for QEMU's refusal.  @g_src_qemu_extra is the other direction -- QEMU
 * states a source the wire does not publish -- which is not scored here
 * because it is not what this census is for; it is counted so the two
 * directions can never be quoted as one number.
 */
GHashTable *g_src_unjustified_sig = nullptr;
GHashTable *g_src_qemu_extra_sig = nullptr;
/*
 * THE SURVIVOR ROWS, KEYED ON QEMU'S OWN DECODE IDENTITY, and the witness
 * that says whether that key is sharp enough to be one.
 *
 * @g_src_survivor_ident is the same population as g_src_unjustified_sig --
 * a published source QEMU's read list does not justify -- re-keyed from the
 * disassembler's mnemonic onto qemu_plugin_insn_decode_id().  A flip that
 * stops taking the source list from the operand walk has to carry these
 * rows, and it can only look them up by something it still has after the
 * walk is gone.
 *
 * @g_src_ident_witness is why the re-key is MEASURED rather than assumed.
 * One decode rule can carry several instructions -- x86 `clflush` decodes
 * through QEMU's NOP row -- so a survivor table keyed on the id alone would
 * hand one instruction's sources to another.  This tally is (decode id,
 * mnemonic) over EVERY row apply_dst() is reached for -- NOT only the rows
 * whose read list QEMU stated, which is the narrower population the
 * survivor tally beside it scores.  The two are deliberately different
 * subjects and @g_src_ident_witness_reached is what says so out loud.
 */
GHashTable *g_src_survivor_ident = nullptr;
GHashTable *g_src_ident_witness = nullptr;
/*
 * THE SAME ROWS FOR THE POPULATION THE CENSUS CANNOT SCORE, and it is a
 * separate table because it is a separate claim.
 *
 * @g_src_survivor_ident's rows say "QEMU stated this instruction's read set
 * and this published register is not in it".  On an instruction whose read
 * list QEMU withheld or reported short, that sentence cannot be said, so
 * those rows are absent from it -- correctly.  What was NOT correct was
 * that they were absent from EVERYTHING: NOT-SCORED was a bare count with
 * no list behind it, and a source-list flip has to carry these registers
 * for exactly the same reason it carries the scored survivors -- after the
 * flip the read list contributes nothing here, so the survivor table is
 * their only supplier.
 *
 * Measured, and this is why the table exists: of the 33 program counters
 * that lost a published source when the operand walk's read arm was
 * deleted as an excursion, 30 sat in this population and not one of them
 * appeared in any identity-keyed list this file printed.
 *
 * The rows carry the SAME columns and the SAME role measurement, so
 * tools/gen_src_survivors.py reads them with the same parser, under a
 * heading that says which claim they are.
 */
GHashTable *g_src_nostate_ident = nullptr;
/*
 * THE COLLISION WITNESS'S OWN POPULATION, so its completeness is a
 * measurement instead of a sentence in its header.
 *
 * Every row the witness site is reached for increments this; the report
 * prints it beside the SUM of the printed counts and the difference is a
 * must-be-0.  Before this existed the witness sat inside the read-list gate
 * while its header claimed the whole population, and the shortfall was
 * invisible: nothing compared what it had seen with what it printed.  A
 * list that cannot state its own coverage cannot be read as coverage.
 */
std::atomic<uint64_t> g_src_ident_witness_reached{0};
/*
 * THE FLIP'S COST, PER PUBLISHED SOURCE, measured against the survivor
 * table rather than argued from it.
 *
 * A source-list flip publishes  QEMU's ordered read list  UNION  the rows
 * champsim_tracer_src_survivors.h carries for this instruction's decode
 * identity.  Whether that union is the set the wire publishes today is a
 * question with two directions and they are counted apart, because one is
 * a LOSS and the other is a GAIN and a single number would be readable as
 * neither:
 *
 *   MISSING  a register the wire publishes today that the union does NOT
 *            contain.  R12.1 forbids it: this is exactly the information
 *            the flip would drop.  MUST BE 0.
 *   EXTRA    a register the union contains that the wire does not publish
 *            today.  Two populations share it -- QEMU-EXTRA (a source the
 *            emulator states and the decode never named) and any register
 *            a survivor row supplies to an instruction that does not want
 *            it.  Tallied by row so the two are separable by inspection.
 *
 * MEASUREMENT ONLY.  Nothing here writes a wire field; the flip that would
 * use this union is not this change.  What it does is make the flip's cost
 * a number BEFORE the flip, which is the discipline the destination side's
 * refuse route already follows.
 */
uint8_t src_survivor_regs(uint32_t decode_id, const InsnFields *f,
                          uint8_t *out, uint8_t cap);
std::atomic<uint64_t> g_src_flip_missing{0};
std::atomic<uint64_t> g_src_flip_extra{0};
std::atomic<uint64_t> g_src_flip_scored{0};
std::atomic<uint64_t> g_src_flip_no_row{0};
GHashTable *g_src_flip_missing_sig = nullptr;
GHashTable *g_src_flip_extra_sig = nullptr;
/*
 * THE SURVIVOR-ROW REFUTATION -- the fabrication instrument that is not
 * circular.
 *
 * g_src_flip_extra above scores "a register a survivor row supplies that the
 * WIRE does not publish", and it reads zero by construction: qemu_named_regs()
 * has already seated the survivor row's own output INTO that wire, so the row
 * is being compared against a list that contains it.  It read 0 on all four
 * ISAs through PASS 45 while TWELVE aarch64 SVE encodings were publishing a
 * predicate or a store-data vector their encoding does not name (exec81 M3),
 * and it would have read 0 for any successor of those.  A number that cannot
 * be anything but zero is not evidence, so it stays -- as the SEATING CHECK
 * it actually is -- and the fabrication question is asked somewhere else.
 *
 * ASKED AGAINST QEMU'S STATED FACTS INSTEAD, never against the wire.  For
 * each register a survivor row supplies to an instruction, the fact recorded
 * is whether QEMU's own stated read list carries it -- named, or inside a
 * stated container under the #277 rule.  Keyed on (decode id, rule,
 * register), so the two tallies below are the same population split by what
 * the emulator said, and NOTHING the wire publishes enters either one.
 *
 * THE REFUTATION IS THE JOIN.  A key that appears in BOTH tables is a rule
 * for which QEMU states that register on some instances and does not on
 * others -- and a SRC_SURV_FIXED row means "the same register on every
 * instruction this rule decodes".  On the instances where QEMU is silent the
 * row is supplying a register the encoding does not carry.  That is exactly
 * the M3 shape: `ld1b` under LD_zpri, where the decodetree pattern leaves Pg
 * free, QEMU now states the governing predicate per instance, and a row
 * frozen at REG_PRED1 fabricates it on every p0 instance.
 *
 * WHY THIS DOES NOT FIRE ON A LEGITIMATE FIXED ROW.  x86 `idivl` reads
 * REG_GPR0 and REG_GPR2 by ISA definition and QEMU states NEITHER on ANY
 * instance, so those keys are silent-only and never join.  A row whose
 * register QEMU always states is stated-only and never joins either -- it is
 * a redundant row, which is a different finding and is reported as one.  The
 * join needs the emulator's own facts to DISAGREE with themselves across
 * instances of one rule, and only an ENCODED operand does that.
 *
 * MEASUREMENT ONLY.  Nothing here writes a wire field.
 */
std::atomic<uint64_t> g_surv_ref_stated{0};
std::atomic<uint64_t> g_surv_ref_silent{0};
GHashTable *g_surv_ref_stated_sig = nullptr;
GHashTable *g_surv_ref_silent_sig = nullptr;
GHashTable *g_surv_ref_short_sig = nullptr;
/*
 * THE ADJUDICATION LEDGER -- the THIRD outcome of the loss direction, and
 * the reason it is not the second.
 *
 * A published source lands in MISSING when neither QEMU's read list nor a
 * survivor row carries it, and that row is an R12.1 violation waiting for a
 * flip to commit it.  Some classes on this wire are in that position for a
 * DIFFERENT reason, and calling them MISSING says something false about
 * them: their deletion was already written, landed, MEASURED AGAINST THE
 * EXTERNAL REFERENCES, and reverted, because the references contradicted
 * the adjudication.  They were not rows nobody had looked at.  They were
 * rows a maintainer had been asked about.
 *
 * THE LEDGER NOW HAS TWO STATES, and a row must be in exactly one:
 *
 *   ADJ_OWED   the question is still in front of the maintainer.  The row
 *              is counted in ADJUDICATION-OWED, printed with its question,
 *              NEVER folded into JUSTIFIED, and NO SOURCE-LIST FLIP MAY
 *              LAND WHILE THE COUNT IS NON-ZERO.
 *
 *   ADJ_R16    the question has been RULED, and the ruling is that the wire
 *              is right.  The row is counted in JUSTIFIED-BY-ADJUDICATION
 *              (R16) and printed with the ruling text, in a column of its
 *              own.  It is still not folded into JUSTIFIED, because
 *              JUSTIFIED means one specific mechanical thing -- QEMU's
 *              ordered read list contains the register -- and it does not
 *              contain these.  An adjudication and a read-list hit are two
 *              different reasons for a row to be right, and a census that
 *              spends them into one column can no longer say which rows
 *              rest on a measurement and which rest on a ruling.
 *
 * THE CLOSURE IS VISIBLE, NEVER SILENT.  A row does not leave this table
 * when it is ruled on; it changes state, keeps its count, and prints the
 * ruling.  The alternative -- deleting the row so ADJUDICATION-OWED reads
 * zero -- is answering a question by arithmetic, which is the failure the
 * whole ledger is shaped against.  A reader who wants to know what happened
 * to riscv64 `fence` finds the row, the ruling and the count in one place.
 *
 * R16 (2026-08-30), the ruling these rows close under, verbatim:
 *
 *   "We record ARCHITECTURAL DEPENDENCIES.  IF THE DEPENDENCY EXISTS IN THE
 *    ISA, OR THE REGISTER IS AN ISA REGISTER, THEN WE RECORD IT.  Does
 *    FENCE depend on the system register contents?  THEN THAT IS A
 *    DEPENDENCY.  I DON'T CARE ABOUT SEMANTICS.  A NOP SEMANTIC STILL HAS
 *    REAL DEPENDENCIES IN THE CHOSEN REGISTER.  MICROARCHITECTURAL
 *    OPTIMIZATIONS SHOULD NOT BE LEAKING INTO THE TRACE.  QEMU
 *    OPTIMIZATIONS SHOULD NOT BE LEAKING INTO THE TRACE.  We should be
 *    recording ALL INSTRUCTIONS THAT EXECUTE.  If the instructions were not
 *    being included, that was a bug.  We should be including all
 *    information those instructions should have."
 *
 * THE ROWS, and what R16 did to each:
 *
 *   riscv64 `fence`, REG_SYS.  The encoding names no register -- both
 *     operands are immediates -- and on that reading the source had no
 *     architectural referent.  But Sail, the architecture's own executable
 *     specification, states ref_src = REG_SYS for FENCE, and the deleted
 *     clause was exactly the menvcfg.FIOM dependency Sail models: FIOM
 *     decides whether the fence's device-ordering bits also order main
 *     memory, so the CSR's value changes what the instruction DOES.  R16
 *     answers the question the row was waiting on -- the dependency exists
 *     in the ISA, so it is recorded, and the emptiness of QEMU's read list
 *     is a QEMU statement gap and not an architectural fact.  ADJUDICATED-
 *     KEEP-R16.
 *
 *   x86_64 `rdsspq`, REG_SSP.  With CET disabled -- the only machine QEMU
 *     models -- the SDM defines the instruction as a NOP.  But XED models
 *     the instruction FORM as SRC {REG_SSP} DST {GPR}, and PIN reports
 *     ref_only = ssp on it.  R16 rules that the instruction form's
 *     dependencies are recorded regardless of the modelled machine's CET
 *     state -- a NOP SEMANTIC STILL HAS REAL DEPENDENCIES IN THE CHOSEN
 *     REGISTER.  ADJUDICATED-KEEP-R16.
 *
 *   x86_64 `rdsspq`, REG_GPR0 -- RETIRED FROM THIS TABLE, and the reason is
 *     the one thing here that is not a keep.  R16's second consequence is
 *     that the GPR is the architectural DESTINATION (XED `SRC {SSP} DST
 *     {RAX}`, iced-x86 `DST {RAX}`, PIN dstset `ref_only=rax`) and that its
 *     source seat was an accident: Capstone reported the operand
 *     access == 0, the instruction classifies GEN_OP_NOP, and the
 *     positional fallback had no destination slot to give it.  The repair
 *     is a REAL BOUNDARY ACCESS at cap_fill_x86_operands (see
 *     cap_x86_is_ssp_dest in disas/capstone.c), after which the register is
 *     published as a destination and is no longer a published source at
 *     all -- so it can no longer reach this table.  ITS ROW IS DELETED
 *     RATHER THAN MARKED KEPT, deliberately: if the boundary repair ever
 *     stops reaching, REG_GPR0 reappears as a published source with no
 *     ledger row and reads MISSING, loudly, on a must-be-0 line.  A KEEP
 *     row would have silenced exactly that alarm.
 *
 * KEYED ON (isa, decode id, MNEMONIC) -- deliberately, and this is NOT a
 * survivor row.  The key kept the ledger honest when x86 decode id
 * 0x0000054b was QEMU's NOP slot carrying `endbr64` (410 census rows)
 * beside `rdsspq` (3): a row keyed on the id alone would have silenced a
 * population it was never adjudicated for.  The CET encodings now have
 * identities of their own (target/i386/tcg/cet_ident.c.inc), so the id
 * below is the rdssp arm's and carries no other instruction -- and the
 * mnemonic stays in the key anyway, because it is what keeps `rdsspd` out
 * (see NO SILENT WIDENING below).  A flip cannot look this table up,
 * because after the flip the mnemonic is gone; that is correct.  This
 * table is a LEDGER, not an input to any wire decision.
 *
 * THE ID MOVED AND THE LEDGER SAID SO.  When the qualification landed, this
 * row's 0x0000054b stopped matching and the register read MISSING on the
 * must-be-0 line -- 3 of them, on the very first battery.  That is the
 * alarm the RETIRED REG_GPR0 row above is described as protecting, firing
 * for real on an id change rather than on a boundary regression, and it is
 * why the id here is updated rather than the row being made id-insensitive.
 *
 * NO SILENT WIDENING.  `rdsspd` shares the adjudication class and has no
 * row here because it has no census row in the corpus this was measured on.
 * If it ever appears it reads MISSING, loudly, and needs its own row and
 * its own status -- which is the behaviour wanted.
 */
enum SrcAdjState {
    SRC_ADJ_OWED = 0,   /* question open; blocks the flip                */
    SRC_ADJ_R16  = 1,   /* ruled by R16: the wire is right, and why      */
};
struct SrcAdjRow {
    unsigned    isa;          /* TraceISA */
    uint32_t    decode_id;
    const char *mnem;
    uint8_t     reg;
    unsigned    state;        /* SrcAdjState */
    const char *text;         /* the question, or the ruling */
};
static const SrcAdjRow g_src_adj_ledger[] = {
    { TRACE_ISA_RISCV, 0xecf2c479u, "fence",  REG_SYS, SRC_ADJ_R16,
      "ADJUDICATED-KEEP-R16.  R16 verbatim: \"We record ARCHITECTURAL "
      "DEPENDENCIES.  IF THE DEPENDENCY EXISTS IN THE ISA, OR THE REGISTER "
      "IS AN ISA REGISTER, THEN WE RECORD IT.  Does FENCE depend on the "
      "system register contents?  THEN THAT IS A DEPENDENCY.  I DON'T CARE "
      "ABOUT SEMANTICS.  A NOP SEMANTIC STILL HAS REAL DEPENDENCIES IN THE "
      "CHOSEN REGISTER.  MICROARCHITECTURAL OPTIMIZATIONS SHOULD NOT BE "
      "LEAKING INTO THE TRACE.  QEMU OPTIMIZATIONS SHOULD NOT BE LEAKING "
      "INTO THE TRACE.\"  menvcfg.FIOM decides what a fence ORDERS, Sail "
      "states ref_src=REG_SYS, and QEMU's empty read list at trans_fence "
      "is the statement gap, not the architecture" },
    { TRACE_ISA_X86,   0xdb9bac2bu, "rdsspq", REG_SSP, SRC_ADJ_R16,
      "ADJUDICATED-KEEP-R16.  R16 verbatim: \"IF THE DEPENDENCY EXISTS IN "
      "THE ISA, OR THE REGISTER IS AN ISA REGISTER, THEN WE RECORD IT.  ... "
      "I DON'T CARE ABOUT SEMANTICS.  A NOP SEMANTIC STILL HAS REAL "
      "DEPENDENCIES IN THE CHOSEN REGISTER.\"  The instruction FORM reads "
      "SSP (XED SRC {REG_SSP}, PIN ref_only=ssp); the modelled machine's "
      "CET state does not remove an ISA dependency.  The id is the rdssp "
      "arm of decode-new.c.inc:1355 (decode-new/NOP@f3=1,modrm=11001...), "
      "not the reserved-NOP slot it used to share with endbr64" },
};
static const SrcAdjRow *src_adj_row(uint32_t decode_id, const char *mnem,
                                    uint8_t reg)
{
    for (unsigned i = 0; i < G_N_ELEMENTS(g_src_adj_ledger); i++) {
        if (g_src_adj_ledger[i].isa == (unsigned)trace_isa &&
            g_src_adj_ledger[i].decode_id == decode_id &&
            g_src_adj_ledger[i].reg == reg &&
            mnem && strcmp(g_src_adj_ledger[i].mnem, mnem) == 0) {
            return &g_src_adj_ledger[i];
        }
    }
    return nullptr;
}
std::atomic<uint64_t> g_src_adj_owed_n{0};
GHashTable *g_src_adj_owed_sig = nullptr;
std::atomic<uint64_t> g_src_adj_r16_n{0};
GHashTable *g_src_adj_r16_sig = nullptr;
/*
 * The two remaining ways an ENV BYTE RANGE stays refused (#226).
 *
 * They are separate tallies because they are separate defects with separate
 * owners.  g_field_unnamed is a range no target DECLARED -- a gap in the
 * CPUArchState statement beside the globals, fixed in QEMU.  Both entries it
 * can carry name the shape, not the offset, because an offset means nothing
 * without the struct it indexes and the shapes are what a reader acts on.
 *
 * g_field_unmapped_name is a range QEMU DID name and the tracer has no
 * generic word for -- a gap in the register table, fixed in its generator.
 * Naming those by their QEMU spelling is the whole point: it is the list a
 * table pass works from.
 */
GHashTable *g_field_unnamed = nullptr;
GHashTable *g_field_unmapped_name = nullptr;
/*
 * The destinations the ENCODING names and the OP STREAM does not carry
 * (#260), on both sides of the same question and split by CAUSE.
 *
 * g_discard_rows counts the statements that landed where the emulator threw
 * the write away -- `cmp` into XZR, `mul`'s destroyed HI/LO, `move $zero`.
 * It is the number that makes the #218 droppable population's fall a
 * measurement rather than an absence.
 *
 * g_indexed_write_rows counts the OTHER cause, and it is counted apart
 * because it is the opposite claim about the same absent op: the emulator
 * PERFORMS this write, through an index only the encoding states.  AArch64's
 * FEAT_MOPS is the class -- `cpyfe`/`cpyfm`/`sete`/`setm` pass one syndrome
 * word and the helper pulls Rd, Rs and Rn out of it.  Folding the two would
 * make g_discard_rows a count of neither thing.
 *
 * g_discard_unmapped_name is the mirror of both: a name QEMU stated and the
 * register table has no generic word for.  Same shape and same fix as
 * g_field_unmapped_name -- the generator's table, not this file.
 */
std::atomic<uint64_t> g_discard_rows{0};
std::atomic<uint64_t> g_indexed_write_rows{0};
/*
 * THE DESTINATION LIST'S SOURCE, both outcomes (#232).
 *
 * g_dst_reseated counts the published destination families whose slot
 * dictionary is QEMU's own write list, in QEMU's order.  g_dst_reseat_refused
 * counts the ones where the two lists are not the same set, so no permutation
 * of the walk's answer is QEMU's and the walk's list stands -- the only route
 * by which the operand walk still decides which register a destination slot
 * is for.  Its signature tally names the mnemonics, so the population is a
 * list and not a remainder.
 */
std::atomic<uint64_t> g_dst_reseated{0};
std::atomic<uint64_t> g_dst_reseat_refused{0};
GHashTable *g_dst_reseat_refused_sig = nullptr;
GHashTable *g_discard_unmapped_name = nullptr;
/*
 * A register QEMU DID give this file a generic word for, stated as WRITTEN
 * by an instruction whose destination family is published -- and which the
 * wire's own destination list does not carry.
 *
 * This is the direction of the two lists' disagreement that nothing counted.
 * dst_precheck() covers the other one: a wire destination with no QEMU write
 * row refuses the whole family (QDEP_R_DST_UNNAMED).  Its mirror was
 * silently dropped, and a silently dropped population is one nobody can say
 * is empty.  It is NOT empty: on the four-ISA workload it is 212 rows, and
 * every one of them names REG_PC.
 *
 * THE PC ROW IS EXCLUDED, AND R10.1 (2026-08-27) SAYS WHY.  R10 read the
 * question as branches and answered it for branches: an instruction the ISA
 * defines as writing the program counter may carry REG_PC as a destination,
 * and every such instruction already does -- the operand walk lists it, and
 * on x86_64 that is 2,726 rows across seven branch classes.  The rows
 * counted HERE are the other thing entirely.  A translation block ends by
 * writing the pc, and QEMU charges that write to whichever instruction the
 * block ended on: a delay-slot `lw` on mipsel, a page-final `mov` on x86_64.
 * The register belongs to the BLOCK, not to the instruction.
 *
 *     "if you are actually referring to a QEMU-behavioral-artifact (not
 *      architecturally justifiable as part of the ISA), then that should
 *      not be getting emitted."
 *
 * R1 (no context), R2 (architectural only) and J2.3 decided this before the
 * amendment restated it, and the count is its own proof of non-architecture:
 * it moves with argv length, because which instruction lands last depends on
 * where the block ends.  Excluding it is not information loss under R12.1 --
 * an artifact is not architectural information, the same category as a
 * Capstone fabrication -- and the exclusion is JUSTIFIED, not pending, so
 * the stats line states the contract rather than promising a ruling.
 *
 *   _pc    -- the artifact population itself.  CORRECT BY CONTRACT and NOT
 *             a must-be-0.  It is counted because a population nobody can
 *             quote is one nobody can say is bounded, and because an
 *             ARCHITECTURAL pc write whose walk failed to list it would
 *             land in this same count -- which is why the adjudication runs
 *             on the wire's own branch_type and is on file, per row, rather
 *             than being asserted here.
 *   _other -- any OTHER named register the machine writes and the wire does
 *             not name.  Unchanged, and still a must-be-0.
 */
GHashTable *g_dst_wire_missing = nullptr;   /* "mnem  REG" -> count */
std::atomic<uint64_t> g_dst_wire_missing_pc{0};
std::atomic<uint64_t> g_dst_wire_missing_other{0};
/*
 * Address slots whose provenance was COMPLETE and named no register, on a
 * template that carries an immediate -- the encoding-derived address, counted
 * because a rule nobody can see fire is a rule nobody can check.  See the
 * immediate-provenance block in the HAS_ADDR section.
 */
std::atomic<uint64_t> g_addr_imm{0};
std::atomic<uint64_t> g_addr_empty_no_imm{0};
/*
 * DESTINATION slots the same rule reached: the write's provenance was
 * COMPLETE and named no register, no load slot and no env range, so the value
 * is the instruction's own encoding and the mask carries the immediate bit.
 * Counted per SLOT, beside the per-instruction refusal buckets, for
 * g_addr_imm's reason -- and because the population it replaces (#227) was
 * refused for as long as one refusal covered three different facts.
 */
std::atomic<uint64_t> g_dst_imm{0};
/*
 * The two DECIDED directions of the encoded-immediate rule (#248), on
 * destination slots whose mask ALSO names registers -- the population that
 * refused wholesale until the provenance bit existed.
 *
 * @g_dst_imm_feeds: the encoding reached this destination and the slot's mask
 * takes the immediate bit beside its registers -- `add $5,(%rax)`'s flags.
 * @g_dst_imm_absent: the decoder stated the immediate, an op read it, and it
 * did not arrive here, so the register-only mask is COMPLETE and abstains
 * from the bit -- `ldr x0,[x1,#8]`, whose #8 is the address's.
 *
 * Both are counted because a rule that only reports the direction it likes
 * cannot be checked: the abstention is a published claim of completeness and
 * is exactly as load-bearing as the bit.
 */
std::atomic<uint64_t> g_dst_imm_feeds{0};
std::atomic<uint64_t> g_dst_imm_absent{0};
/*
 * ACCUMULATES: destination slots published with the destination register in
 * their own mask (#228).
 *
 * Counted because this population was a refusal until the emitter could say
 * which self-reference is architectural, and a flip from "refused" to
 * "published" that reports no number is a claim nobody can check.  Every row
 * here is an instruction that takes its destination as a source -- R7's test
 * says the regfile must respect the edge and R3 says the tracer does not
 * elide it for being redundant.  The two shapes that are NOT this are gone
 * before they reach here: see dst_precheck().
 */
std::atomic<uint64_t> g_dst_accum{0};
/*
 * DESTINATION SLOTS whose register-only mask is complete because the ONE
 * encoded field the instruction carries is a field the architecture does not
 * define as a dataflow operand (#252).  MIPS' `teq rs,rt,code` and `break
 * code` are the class, and the number is here rather than implied because
 * the row it replaces published `dst_dep = IMM` -- a claim that the CP0
 * exception state depends on the trap code, which is false.  A correction
 * that reports no count is a claim nobody can check.
 */
std::atomic<uint64_t> g_dst_imm_non_dataflow{0};
/*
 * THE LAZY-FLAG INTERPRETATION, counted in the three directions it can go
 * (#265/#184).  x86 materialises EFLAGS on demand: an instruction that only
 * READS flags still writes cc_op, and re-expresses cc_src through the
 * compute helper, so QEMU's write list named REG_FLAGS on 111 `jcc`, 6
 * `cmov` and 2 `setcc` PCs that write no flag the ISA defines.  Those rows
 * were the whole of the `_other` MUST-BE-0.
 *
 * @g_dst_repr_selector: writes to a declared SELECTOR, skipped.  R10.1's
 * category reached from the register side: emulator bookkeeping is not
 * architectural information.
 *
 * @g_dst_repr_change: writes struck as a CHANGE OF REPRESENTATION -- the
 * destination is a lowered register and the write's whole provenance is
 * inside that register's own set of globals.  A value re-expressed, not a
 * value produced.  This is also where R7.1 lands `inc`'s preserved CF: the
 * `cc_src <- cc_src` that carries it is this shape, so FLAGS stops appearing
 * in its own destination mask, which R7.1 says it never should have.
 *
 * @g_dst_repr_refused: the direction that would be a LOSS, so it is a
 * must-be-0 rather than a number to admire.  Every QEMU write to a register
 * the WIRE names as a destination was struck above, so the row vanished and
 * the family refuses (QDEP_R_DST_UNNAMED) rather than publishing.  The shape
 * that would land here is `stc`/`clc`/`cmc`: materialise, then set one bit
 * with a translator constant that no note distinguishes from the
 * materialisation's own inputs.  It has no subject in the corpus; the
 * coverage path is a QEMU-side note at those emitters saying the write
 * SUPPLIES a value, which is the same shape #205 and #230 used.
 */
std::atomic<uint64_t> g_dst_repr_selector{0};
std::atomic<uint64_t> g_dst_repr_change{0};
std::atomic<uint64_t> g_src_justified{0};
std::atomic<uint64_t> g_src_unjustified{0};
std::atomic<uint64_t> g_src_nostate{0};
std::atomic<uint64_t> g_src_qemu_extra{0};
std::atomic<uint64_t> g_src_insn_scored{0};
std::atomic<uint64_t> g_src_insn_nostate{0};
std::atomic<uint64_t> g_src_wide{0};
/*
 * READ-LIST MEMBERS THE TRACER'S VOCABULARY DROPS.
 *
 * note_src() SKIPS a member of QEMU's ordered read list it has no generic
 * word for, and keeps the instruction scorable.  That is the right choice --
 * refusing the whole instruction on one unnamed member would hide every
 * other entry's verdict behind a vocabulary gap -- but it is not free, and
 * until these counters existed the cost was invisible in exactly the
 * direction that matters: a skipped member cannot justify anything, so a
 * source the wire publishes CORRECTLY is reported UNJUSTIFIED, and the
 * survivor table is then asked to carry a row for a fact QEMU did state.
 *
 * Split by WHY the member could not be named, because the three have three
 * different coverage paths: a global outside the target's register count, a
 * CPUArchState byte range no declared regfile covers, and a byte range with
 * a QEMU field name that generic_for_field_name() does not map.  The last
 * is the one #218/#226/#237 closed for the WRITE side; this is the read
 * side of the same vocabulary.
 */
std::atomic<uint64_t> g_src_skip_global{0};
/*
 * ...and the fourth outcome, which is NOT a coverage path: the member is
 * QEMU's own lowering state and must never have a word.  Counted apart so
 * `global-word` keeps meaning "a register this file is missing a word for"
 * -- see nonarch_lowering_reason().
 */
std::atomic<uint64_t> g_src_skip_lowering{0};
std::atomic<uint64_t> g_src_skip_field_unnamed{0};
std::atomic<uint64_t> g_src_skip_field_generic{0};
std::atomic<uint64_t> g_src_skip_other{0};
std::atomic<uint64_t> g_src_skip_insns{0};
GHashTable *g_src_skip_sig = nullptr;    /* "reason  name" -> count */
std::atomic<uint64_t> g_dst_repr_refused{0};
GHashTable *g_dst_repr_sig = nullptr;       /* "mnem  REG" -> count */
GHashTable *g_dst_repr_refused_sig = nullptr;
/* The lowered registers this target has: generic name -> global count. */
GHashTable *g_lowered_reg = nullptr;
/*
 * THE #236 FLIP'S REFUSE ROUTE, COUNTED BEFORE THE FLIP EXISTS.
 *
 * An instruction whose wire destination list is non-empty AND whose QEMU
 * write list is short by a register the source cannot name (aarch64 MOPS,
 * `env->xregs[mops_destreg(syndrome)]`).  The flip cannot publish QEMU's
 * list for these -- it would delete an architectural destination -- so the
 * flip must REFUSE the instruction, and this is how many that is.
 *
 * Nothing is refused today: the row counts, the wire does not move.
 */
std::atomic<uint64_t> g_dst_would_refuse_unbounded{0};
/*
 * Every refused row by MNEMONIC and reason.  A refusal count that cannot say
 * WHICH instructions refused cannot be adjudicated, and an unadjudicated
 * refusal is a published all-inputs default nobody ever looks at again.  The
 * shadow tallies this replaces asked what CAPSTONE would have said; this one
 * asks what QEMU could not say, which is the only question left.
 */
GHashTable *g_refusal_sig   = nullptr;   /* "mnem  reason" -> count */

/* ==================================================================
 * THE EMISSION CENSUS (R12 / R12.1)
 *
 * Per INSTRUCTION, not per slot: whether the HAS_REG block exists, and
 * on whose authority.  The four buckets partition every instruction
 * qdep_apply() decided for, so they sum to that population and a row
 * cannot hide between them.
 * ================================================================== */
/* QEMU stated a dependency fact -- a destination provenance it could state
 * in full, or a store datum it could state in full -- and the block exists
 * because of that.  This is R12's rule and it is the only rule. */
std::atomic<uint64_t> g_blk_qemu{0};
/* QEMU stated nothing this instruction could carry, and the refiner had
 * content.  The block publishes exactly as it published before the flip:
 * a NAMED SURVIVOR under R12.1, on the coverage list dumped by mnemonic
 * and cause below.  Never a default, never a drop, never an endpoint. */
std::atomic<uint64_t> g_blk_survivor{0};
/* Neither side had anything.  No block, and the format's own all-to-all
 * over-approximation is what the consumer reads -- which is what it read
 * before, for the same rows. */
std::atomic<uint64_t> g_blk_absent{0};
/* A QEMU-caused block (its store data is QEMU's) on an instruction whose
 * DESTINATION slots QEMU could not state, so those slots still carry the
 * refiner's masks.  Counted apart because such a block's two halves come
 * from two sources and a consumer cannot tell which is which -- these are
 * survivors too, and they are on the same coverage list. */
std::atomic<uint64_t> g_blk_mixed{0};
/*
 * The same shape with no refiner answer either: the destination slots go out
 * as the format's own all-inputs default, written out.  Not a survivor --
 * there is nothing surviving -- and not a loss, because that default is
 * bit-for-bit what the consumer read when the block did not exist.
 */
std::atomic<uint64_t> g_blk_mixed_default{0};
/*
 * THE MUST-BE-0, AND IT IS A DIFFERENCE RATHER THAN A TAUTOLOGY.
 *
 * @g_fact_stated counts a QEMU dependency fact where it is ESTABLISHED --
 * once in apply_dst() for a destination family it wrote in full, once in
 * the store-data tail for a datum it stated with a slot to state it in.
 * @g_fact_carried counts the same facts where they are CONSUMED, inside
 * decide_block(), on the branch that turns the block on.  Equal by
 * construction only while every path through qdep_apply() ends in
 * decide_block(); an early return that skips it -- which is precisely the
 * shape of the gate R12 deleted, and precisely how it would come back --
 * leaves a fact stated and not carried, and the difference is non-zero.
 *
 * Written as two counters and not one flag because a counter that can only
 * be incremented next to the line that makes it impossible proves nothing.
 */
std::atomic<uint64_t> g_fact_stated{0};
std::atomic<uint64_t> g_fact_carried{0};
/* ==================================================================
 * THE SAME CENSUS FOR THE **ADDRESS** BLOCK (#264).
 *
 * R12 gave the HAS_REG block's existence to QEMU's stated facts and left
 * HAS_ADDR where it was, which is how `rep stosq` came to publish neither:
 * the address family refused as a whole on the one access QEMU could not
 * state, and the wire lost the one it had stated in full.  The rule is now
 * the same rule -- the block exists when QEMU stated an address fact for an
 * access of this instruction -- and it needs the same three-way census, or
 * the flip is an argument rather than a measurement.
 * ================================================================== */
/* Every access's address was QEMU's: the block is wholly QEMU's. */
std::atomic<uint64_t> g_addr_blk_qemu{0};
/* SOME access's address was QEMU's and some was not.  The block exists --
 * a stated fact causes it -- and the slots QEMU could not state publish the
 * format's own all-inputs default WRITTEN OUT, exactly as the destination
 * half does in decide_block()'s mirror-image case.  Never the refiner's
 * mask: a family whose source has flipped may not have slots still quietly
 * carrying the old one. */
std::atomic<uint64_t> g_addr_blk_mixed{0};
/* No access's address was QEMU's, so there is no fact to carry and no
 * block.  The consumer is at the format's own all-to-all
 * over-approximation, which is what it read before. */
std::atomic<uint64_t> g_addr_blk_absent{0};
/* Slots inside a MIXED block that went out at that default.  Counted only
 * where the block EXISTS: an unstated slot on an instruction with no block
 * publishes nothing at all, and folding the two together would put a number
 * beside a sentence that is not about it. */
std::atomic<uint64_t> g_addr_slot_default{0};
/*
 * The address side's must-be-0, and it is a difference for the same reason
 * the register side's is: @g_addr_fact_stated counts an address QEMU stated
 * where it is ESTABLISHED, in qdep_apply()'s per-access loop, and
 * @g_addr_fact_carried counts it where it is CONSUMED, in decide_block() on
 * the branch that turns the bit on.  A path that establishes an address and
 * returns without reaching decide_block() -- the shape of the gate this
 * change deletes -- leaves the two unequal.
 */
std::atomic<uint64_t> g_addr_fact_stated{0};
std::atomic<uint64_t> g_addr_fact_carried{0};
/*
 * The named-survivor list itself: every surviving row by MNEMONIC and by
 * the reason QEMU could not state it, which IS the coverage path -- the
 * reason names the emitter or the decoder that has to learn to state the
 * fact for the row to stop surviving.  R12.1 requires the census to exist;
 * this is it.
 */
GHashTable *g_survivor_sig  = nullptr;   /* "mnem  reason" -> count */

const char *state_name(unsigned s);

void tally(GHashTable **t, const char *key)
{
    g_mutex_lock(&g_tally_lock);
    if (!*t) {
        *t = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, nullptr);
    }
    gpointer v = g_hash_table_lookup(*t, key);
    g_hash_table_insert(*t, g_strdup(key),
                        GUINT_TO_POINTER(GPOINTER_TO_UINT(v) + 1));
    g_mutex_unlock(&g_tally_lock);
}

void dump_tally(GString *report, GHashTable *t, const char *heading)
{
    g_string_append_printf(report, "\n%s\n", heading);
    if (!t || g_hash_table_size(t) == 0) {
        g_string_append(report, "  (none)\n");
        return;
    }
    GList *keys = g_hash_table_get_keys(t);
    keys = g_list_sort_with_data(
        keys, [](gconstpointer a, gconstpointer b, gpointer u) -> gint {
            GHashTable *h = (GHashTable *)u;
            guint ca = GPOINTER_TO_UINT(g_hash_table_lookup(h, a));
            guint cb = GPOINTER_TO_UINT(g_hash_table_lookup(h, b));
            return ca == cb ? g_strcmp0((const char *)a, (const char *)b)
                            : (cb > ca ? 1 : -1);
        }, t);
    for (GList *l = keys; l; l = l->next) {
        g_string_append_printf(report, "  %8u  %s\n",
            GPOINTER_TO_UINT(g_hash_table_lookup(t, l->data)),
            (const char *)l->data);
    }
    g_list_free(keys);
}

/*
 * The SUM of a tally's counts, which is the only way to ask a printed list
 * how much of its population it actually printed.  g_hash_table_size() gives
 * the number of DISTINCT keys and says nothing about coverage: a list can
 * hold 241 rows and account for 7,305 of 7,319 reached instructions, and the
 * shortfall is invisible in both the row count and the rows themselves.
 */
/*
 * @g_tally_lock is a plain GMutex and is NOT recursive, and the report's
 * whole dump_tally() sequence runs inside it, so the form that takes the
 * lock cannot be called from there -- it wedges the process at close, with
 * an empty sidecar and no diagnostic, which is exactly how this was found.
 * Two entry points, and the split is named rather than left to a caller's
 * memory: this one requires the lock to be HELD.
 */
uint64_t tally_total_locked(GHashTable *t)
{
    uint64_t n = 0;

    if (t) {
        GHashTableIter it;
        gpointer k, v;

        g_hash_table_iter_init(&it, t);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            n += GPOINTER_TO_UINT(v);
        }
    }
    return n;
}

/* ...and this one TAKES it, for callers outside the report's held region. */
uint64_t tally_total(GHashTable *t)
{
    uint64_t n;

    g_mutex_lock(&g_tally_lock);
    n = tally_total_locked(t);
    g_mutex_unlock(&g_tally_lock);
    return n;
}

/*
 * THE COMPLETENESS CHECK'S OWN FALSIFIER, run before anything can be scored
 * by it.
 *
 * The check the report makes is "rows reached == rows printed".  A check
 * that can only say yes proves nothing, so this builds a tally by hand,
 * confirms the sum tracks every increment (including repeats of one key,
 * which is exactly how a collision row is spelled), and then plants the
 * defect the real one had -- a row reached and NOT tallied -- and requires
 * the arithmetic to show the shortfall.  The counts are printed by the
 * caller; a failure is loud and refuses.
 */
static void witness_completeness_selftest(void)
{
    GHashTable *t = nullptr;
    uint64_t reached = 0;
    unsigned bad = 0;

    /* ARM 1: an empty tally over an empty population is complete. */
    if (tally_total(t) != reached) {
        bad++;
    }

    /* ARM 2: three reached rows, two distinct keys, all tallied. */
    for (int i = 0; i < 3; i++) {
        tally(&t, i == 2 ? "00000001 rule-b mnem-b" : "00000000 rule-a mnem-a");
        reached++;
    }
    if (g_hash_table_size(t) != 2 || tally_total(t) != 3 || reached != 3) {
        bad++;
    }
    if (tally_total(t) != reached) {
        bad++;
    }

    /* ARM 3: THE PLANT -- a row reached and not tallied.  This is the
     * defect the witness carried: the site was reached, the tier counters
     * moved, and the list said nothing.  The check must see it. */
    reached++;
    if (tally_total(t) >= reached) {
        bad++;                  /* the shortfall was NOT visible */
    }
    if (reached - tally_total(t) != 1) {
        bad++;                  /* ...or was mis-sized */
    }

    /* ARM 4: tallying the missed row restores completeness. */
    tally(&t, "00000002 rule-c mnem-c");
    if (tally_total(t) != reached) {
        bad++;
    }

    g_hash_table_destroy(t);
    if (bad) {
        fprintf(stderr,
                "champsim_tracer: witness completeness selftest FAILED "
                "(%u arm(s)) -- the reached-vs-printed check cannot be "
                "trusted, so no coverage claim from it may be read.\n", bad);
        abort();
    }
}

void note_refusal(const char *mnem, unsigned st, const char *fam,
                  const char *detail)
{
    char *k = g_strdup_printf("%-10s %s  %s%s%s", mnem ? mnem : "?", fam,
                              state_name(st),
                              (detail && *detail) ? " -- " : "",
                              (detail && *detail) ? detail : "");
    tally(&g_refusal_sig, k);
    g_free(k);
}

/*
 * One named survivor, keyed the way the refusal census is keyed, because the
 * reason a row survives IS the reason QEMU could not state it.  A survivor
 * whose cause cannot be named is a survivor nobody can retire, and R12.1's
 * "shrinking coverage work list" would be a phrase rather than a list.
 */
void note_survivor(const char *mnem, unsigned st, const char *detail)
{
    char *k = g_strdup_printf("%-10s %s%s%s", mnem ? mnem : "?",
                              state_name(st),
                              (detail && *detail) ? " -- " : "",
                              (detail && *detail) ? detail : "");
    tally(&g_survivor_sig, k);
    g_free(k);
}

bool src_container_range(const char *nm, uint8_t *lo, uint8_t *hi);
void container_rule_selftest(void);

void qdep_init(void)
{
    /*
     * The containment rule's falsifier, run before anything can be scored
     * by it.  See container_rule_selftest() for the arms.
     */
    container_rule_selftest();
    /*
     * And the completeness check's own falsifier, for the same reason: a
     * coverage number nobody can make wrong is not a coverage number.
     */
    witness_completeness_selftest();

    bool expected = false;
    if (!g_tried.compare_exchange_strong(expected, true)) {
        return;
    }
    if (!qemu_plugin_dataflow_abi_ok(
            QEMU_PLUGIN_DATAFLOW_VERSION,
            (uint32_t)sizeof(qemu_plugin_dataflow_field),
            (uint32_t)sizeof(qemu_plugin_dataflow_status))) {
        g_refusal = "ABI handshake refused: this plugin and this qemu were "
                    "built against different dataflow versions";
        return;
    }
    g_nregs = qemu_plugin_dataflow_nregs();
    g_prov_words = qemu_plugin_dataflow_prov_words();
    if (g_nregs == 0 || g_prov_words == 0) {
        g_refusal = "target exposes no dataflow namespace";
        return;
    }
    g_gen_of_reg.assign(g_nregs, (uint8_t)REG_ID_COUNT);
    for (unsigned i = 0; i < g_nregs; i++) {
        const char *nm = qemu_plugin_dataflow_reg_name(i, nullptr, nullptr);
        if (nm) {
            /* Two stages, the same two the instrument uses.  The fold layer
             * is not optional: riscv64's x8 is spelled "x8/s0" by TCG and
             * "fp" by the GDB stub, and leaving the fold out refused 719
             * riscv64 instructions for a gap that was in this map rather
             * than in QEMU's answer. */
            uint8_t gen = generic_for_qemu_name(nm);
            if (gen == REG_ID_COUNT) {
                gen = fold_nonarch(nm);
            }
            g_gen_of_reg[i] = gen;
        }
    }
    /*
     * The lowered-register map, read off QEMU once (#265).  Both halves are
     * QEMU's answers: which globals it declared SELECTORS, and how many of
     * them fold to one architectural name.  Nothing here consults a
     * mnemonic, an opcode taxonomy or a decoder -- J7 and R12 forbid keying
     * this decision on any of them, and the shape does not need one.
     */
    g_reg_is_selector.assign(g_nregs, 0);
    g_gen_nglobals.fill(0);
    for (unsigned i = 0; i < g_nregs; i++) {
        if (qemu_plugin_dataflow_reg_is_repr_selector(i)) {
            g_reg_is_selector[i] = 1;
        }
        if (g_gen_of_reg[i] < REG_ID_COUNT) {
            g_gen_nglobals[g_gen_of_reg[i]]++;
        }
    }
    /*
     * The lowered registers this target actually has, tallied so the
     * interpretation's SUBJECT is a measurement on every ISA and not an
     * x86 assumption.  A zero in the change-of-representation counter means
     * something only when this list is non-empty: aarch64 lowers NZCV onto
     * four globals exactly as x86 lowers EFLAGS onto four, and its zero is
     * therefore the negative control -- the rule is live there and does not
     * fire, because ARM's flag writes carry values.
     */
    for (unsigned g = 0; g < REG_ID_COUNT; g++) {
        if (g_gen_nglobals[g] >= 2) {
            char *k = g_strdup_printf("%-12s %u globals",
                                      generic_reg_name_or_unknown((uint8_t)g),
                                      (unsigned)g_gen_nglobals[g]);
            tally(&g_lowered_reg, k);
            g_free(k);
        }
    }
    g_live = true;
}

/*
 * Is this write a CHANGE OF REPRESENTATION rather than a value?
 *
 * True when the destination is a LOWERED register -- two or more TCG globals
 * fold to its one architectural name -- and the write's whole provenance is
 * inside that same name.  x86's `gen_compute_eflags()` is the shape: it
 * computes EFLAGS from cc_op/cc_dst/cc_src/cc_src2 and puts the answer back
 * in cc_src, so the value is re-expressed and not changed, and QEMU's own
 * dump measures it clean (106 such writes on the four-ISA workload, cc_src
 * x94 and cc_dst x12, with 0 mixed cases).
 *
 * THE LOWERING COUNT IS WHAT MAKES THIS SAFE, and it is not decoration.
 * `add %rax,%rax` writes rax with rax in its provenance and is a genuine
 * ACCUMULATE (#228) whose edge R7/R3 require; the difference is that RAX has
 * exactly one global, so no write to it can be moving a value between two
 * spellings of the same register.  Dropping the count would delete every
 * accumulate on every ISA.
 *
 * AN EMPTY PROVENANCE IS NOT THIS.  `xor %rax,%rax` folds to a constant, so
 * the flags it really does define arrive with nothing named -- and reading
 * that as a re-expression would delete an architectural write on 252 x86_64
 * PCs, measured.  A representation change always names where it read the
 * old representation from; that is what makes it one.  Likewise a load slot
 * or the encoded-immediate bit puts the value's source outside the register,
 * so neither is this shape either.
 *
 * @regs/@n are the fold's output in GENERIC ids, which is the coordinate the
 * comparison has to be made in: cc_op, cc_dst, cc_src and cc_src2 all fold
 * to REG_FLAGS, so a provenance naming all four arrives here as one entry.
 */
static bool is_repr_change(uint8_t gen, const uint8_t *regs, uint8_t n,
                           uint8_t load_slots, uint8_t saw_imm)
{
    if (g_gen_nglobals[gen] < 2 || n == 0 || load_slots || saw_imm) {
        return false;
    }
    for (uint8_t i = 0; i < n; i++) {
        if (regs[i] != gen) {
            return false;
        }
    }
    return true;
}

/* Add @gen to @regs, keeping it sorted and unique.  false when full. */
bool add_reg(uint8_t *regs, uint8_t *n, uint8_t gen)
{
    for (uint8_t i = 0; i < *n; i++) {
        if (regs[i] == gen) {
            return true;
        }
    }
    if (*n >= QDEP_MAX_ADDR_REGS) {
        return false;
    }
    regs[(*n)++] = gen;
    return true;
}

/*
 * The generic word for an env byte range, by the name QEMU gives it.
 *
 * R5's case exactly: an env offset is a register whose storage no TCG global
 * happens to name, and the offset IS the identity.  QEMU inverts it -- each
 * target declares its register files beside the globals it registers -- and
 * this puts the answer through the same two-stage name map the globals go
 * through, because a register must not get one generic word by one route and
 * a different one by the other.
 *
 * REG_ID_COUNT when the range has no name (nothing declared covers it, or it
 * reaches past one register) or has a name the tracer's vocabulary does not
 * carry.  Both are refusals, and the caller tallies which.
 */
/*
 * Tally an env range by its OFFSET.
 *
 * The offset is meaningless without the struct it indexes and is exactly
 * what a reader needs: `pahole`-ing CPUArchState at that number names the
 * field, and naming it is the whole of the follow-up work.  A single
 * "some ranges are undeclared" key would report that a gap exists and
 * nothing about where.
 */
void tally_field_off(GHashTable **t, uint32_t off)
{
    char k[48];

    g_snprintf(k, sizeof(k), "env offset %u (0x%x), no target declaration",
               off, off);
    tally(t, k);
}

/*
 * THE COMPOSED-REGISTER CONTAINMENT TABLE (#277).
 *
 * #277 settled that a member field and its container are ONE composed
 * register and that the container covers the member.  This table is the
 * read side of that contract: QEMU states the container -- it is what the
 * emulator's storage and its helpers actually take -- and the wire
 * publishes the member the encoding selects.  Neither is wrong, and a
 * census that scored them as disagreement was reporting a granularity
 * difference as a missing dependency.
 *
 * Keyed on QEMU'S SPELLING, not on a generic word, because the container
 * is exactly the thing the vocabulary has no member-level word for -- that
 * is what makes it a container.  Each row is measured, not predicted:
 *
 *   fcr31    mipsel's FP control/status word.  `bc1t` tests one FCC bit;
 *            QEMU's ordered read list names `fcr31`, which is where the
 *            eight FCC bits live (MIPS64 Vol II, FCSR bits 23 and 25-31).
 *            The wire names REG_PRED0..7, the bit the encoding selects.
 *
 *   fpregs   x86's x87 stack.  Every instruction that reads the stack
 *            reaches it through a helper that takes the whole array, so
 *            what QEMU states is off=fpregs size=128 -- the file.  The wire
 *            names ST(0) as REG_FPR0.  The array cannot be declared per
 *            element (it is indexed by PHYSICAL register while ST(i) is
 *            relative to env->fpstt), which is why the container is the
 *            only statement available and why it is the right one.
 *
 * ONE DIRECTION ONLY.  A container justifies a member; it is never
 * published, never enters the flip's union, and never counts as a source
 * QEMU states that the wire lacks.  The selftest below is what proves the
 * rule cannot reach an unrelated register.
 */
bool src_container_range(const char *nm, uint8_t *lo, uint8_t *hi)
{
    if (!nm || !*nm) {
        return false;
    }
    if (!strcmp(nm, "fcr31")) {
        *lo = REG_PRED0;
        *hi = (uint8_t)(REG_PRED0 + 7);
        return true;
    }
    if (!strcmp(nm, "fpregs")) {
        *lo = REG_FPR0;
        *hi = (uint8_t)(REG_FPR0 + 7);
        return true;
    }
    return false;
}

std::atomic<uint64_t> g_cont_selftest_arms{0};
std::atomic<uint64_t> g_cont_selftest_failed{0};

/*
 * The rule's own falsifier, run once at install.
 *
 * Four arms, and the last two are the point: a rule that justified
 * everything would make the census's zero vacuous, so the negative arms are
 * what make the positive ones mean anything.
 */
void container_rule_selftest(void)
{
    struct { const char *nm; uint8_t reg; bool want; } arms[] = {
        /* POSITIVE: the container covers its own member. */
        { "fcr31",  REG_PRED0,                 true  },
        { "fpregs", REG_FPR0,                  true  },
        /* NEGATIVE: a container does NOT cover an unrelated register. */
        { "fcr31",  REG_GPR0,                  false },
        { "fpregs", REG_GPR0,                  false },
        /* NEGATIVE: a container does not cover PAST its own bank. */
        { "fcr31",  (uint8_t)(REG_PRED0 + 8),  false },
        { "fpregs", (uint8_t)(REG_FPR0 + 8),   false },
        /* NEGATIVE: an ordinary register is not a container at all. */
        { "rax",    REG_GPR0,                  false },
        { "fcsr",   REG_FCSR,                  false },
    };

    for (const auto &a : arms) {
        uint8_t lo = 0, hi = 0;
        bool got = src_container_range(a.nm, &lo, &hi) &&
                   a.reg >= lo && a.reg <= hi;

        g_cont_selftest_arms.fetch_add(1, std::memory_order_relaxed);
        if (got != a.want) {
            g_cont_selftest_failed.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

uint8_t generic_for_field_name(const char *nm)
{
    uint8_t gen;

    if (!nm || !*nm) {
        return REG_ID_COUNT;
    }
    gen = generic_for_qemu_name(nm);
    if (gen == REG_ID_COUNT) {
        gen = fold_nonarch(nm);
    }
    /*
     * REG_NONE is 0, so it passes every `< REG_ID_COUNT` test while meaning
     * the opposite: the register table carries the register and states that
     * it has NO generic word.  Returning it would put a dependency on
     * "REG_NONE" into a published mask, which is a fabricated edge.
     *
     * The rows that read that way are not the same set they were.  A row
     * Capstone cannot name USED to be REG_NONE by construction, because its
     * generic ID came from whichever Capstone constant routed to it and no
     * constant did -- so x86's `fctrl` said "no word" while REG_FPCW is
     * exactly the word for it.  QEMU_ONLY_REG_IDS in the generator answers
     * that from QEMU's side; what still reaches here is a register whose
     * ROLE the vocabulary has no class for (x86 efer, the segment bases).
     */
    if (gen == REG_NONE) {
        return REG_ID_COUNT;
    }
    return gen;
}

/*
 * The reservation monitor's VALUE half, by the name its target gave the TCG
 * global.  Three targets lower store-conditional onto a cmpxchg whose
 * COMPARE operand is this global, so it shows up as one input of the datum
 * the access stores.
 *
 * It is not an unmapped register and it must not be given a generic word:
 * R7.7 already ruled that reservation state "is a product of the
 * instruction, not the register used".  It is the emulation-artefact
 * category f46873a738 established for #177, and it is named here so the
 * census can say so instead of filing it under a decoder gap.
 */
bool is_monitor_value(const char *nm)
{
    return nm && (!strcmp(nm, "exclusive_val") ||     /* aarch64 */
                  !strcmp(nm, "exclusive_high") ||    /* aarch64, 128-bit */
                  !strcmp(nm, "load_val") ||          /* riscv64 */
                  !strcmp(nm, "llval"));              /* mipsel */
}

/*
 * Fold one access's provenance -- address or store-data -- into @regs.
 *
 * UNION rather than replace, because one static memory OPERAND expands into
 * as many architectural accesses as the form performs -- AArch64
 * `ld4 {v0.16b-v3.16b}, [x1]` is one operand and 64 accesses -- and the
 * wire carries one mask per operand.  The format says every access an
 * operand expands into computes its address from the same registers; if a
 * target ever contradicts that, the union is the direction that keeps the
 * mask from being short.
 *
 * @load_slots is non-NULL for the DATA arm and NULL for the ADDRESS arm, and
 * that is the whole difference between them.  A store's datum genuinely may
 * be a value this same instruction loaded -- every read-modify-write is that
 * shape -- and the HAS_REG mask HAS a bit per load slot to carry it.  An
 * ADDRESS mask has no such bits, because the layout is built on addresses
 * computing before any load fires, so the same provenance bit is a refusal
 * there and a recorded slot here.
 */
QDepState fold_prov(const uint64_t *words, uint8_t *regs, uint8_t *n,
                    uint8_t *load_slots, uint8_t *saw_imm)
{
    for (unsigned b = 0; b < g_prov_words * 64; b++) {
        unsigned slot;

        if (!(words[b / 64] & (1ULL << (b % 64)))) {
            continue;
        }
        if (b < g_nregs) {
            uint8_t gen = g_gen_of_reg[b];
            if (gen >= REG_ID_COUNT) {
                const char *nm =
                    qemu_plugin_dataflow_reg_name(b, nullptr, nullptr);
                if (is_monitor_value(nm)) {
                    tally(&g_monitor_name, nm);
                    return QDEP_R_EMU_MONITOR;
                }
                tally(&g_unmapped_name, nm ? nm : "?");
                return QDEP_R_UNMAPPED;
            }
            if (!add_reg(regs, n, gen)) {
                return QDEP_R_WIDE;
            }
        } else if (qemu_plugin_dataflow_prov_zero_reg(b)) {
            /*
             * The architectural ZERO register, stated by the accessor that
             * resolved the operand.  QEMU folds it to a constant, so without
             * that note the set would be SHORT by exactly the register the
             * encoding names -- which is what R7.3 refused and what the 575
             * `ir-stdata-missing:REG_ZERO` rows were.
             */
            if (!add_reg(regs, n, (uint8_t)REG_ZERO)) {
                return QDEP_R_WIDE;
            }
        } else if (qemu_plugin_dataflow_prov_encoded_imm(b)) {
            /*
             * THE INSTRUCTION'S OWN ENCODED IMMEDIATE, stated by the decoder
             * that materialised it (#248).  Not a register, so nothing is
             * added to @regs; reported through @saw_imm to the one family
             * that has a question only it can answer -- whether a
             * destination whose mask names registers ALSO depends on the
             * encoding.
             *
             * Consumed rather than refused on every arm, including the ones
             * that pass NULL.  The address and store-data families reached
             * their own settled reading of the encoding before this bit
             * existed (4a104e0be4, fb92a61ea4) and both key it on the mask
             * being EMPTY, which a bit that adds no register leaves it.
             * Refusing here instead would have turned every RIP-relative
             * address and every immediate store into a refusal for carrying
             * a fact.
             */
            if (saw_imm) {
                *saw_imm = 1;
            }
        } else if (qemu_plugin_dataflow_prov_memop(b, &slot)) {
            if (!load_slots) {
                return QDEP_R_UNREPRESENTABLE;
            }
            if (slot >= QDEP_MAX_ACCESS) {
                return QDEP_R_WIDE;
            }
            *load_slots |= (uint8_t)(1u << slot);
        } else {
            /*
             * An env byte range -- a register whose storage no TCG global
             * names.  QEMU inverts the offset for us (each target declares
             * its files beside its globals), so the answer is a NAME and
             * goes through the same map every global's does.
             *
             * What still refuses: a range nothing declared covers, one that
             * reaches past a single register -- a helper handed the whole
             * vector file starts at the same byte as an access to its first
             * element, and taking the first would publish a SHORT set -- and
             * a register the tracer's vocabulary has no word for.  Each is
             * tallied by name so the residual is a list, not an adjective.
             */
            char fnm[64];
            uint8_t gen;

            uint32_t foff = 0;

            qemu_plugin_dataflow_prov_field(b, &foff);
            if (!qemu_plugin_dataflow_prov_field_reg(b, fnm, sizeof(fnm))) {
                tally_field_off(&g_field_unnamed, foff);
                return QDEP_R_FIELD;
            }
            if (is_monitor_value(fnm)) {
                tally(&g_monitor_name, fnm);
                return QDEP_R_EMU_MONITOR;
            }
            gen = generic_for_field_name(fnm);
            if (gen >= REG_ID_COUNT) {
                tally(&g_field_unmapped_name, fnm);
                return QDEP_R_FIELD;
            }
            if (!add_reg(regs, n, gen)) {
                return QDEP_R_WIDE;
            }
        }
    }
    return QDEP_OK;
}

/*
 * Turn a generic-register set into a mask over this template's src slots.
 *
 * Returns false when a named register occupies no slot -- there is no bit
 * to set, so the mask would be SHORT.  That is the disqualifying direction
 * and the whole instruction is refused for it.
 */
bool regs_to_mask(const InsnFields *f, const uint8_t *regs, uint8_t n,
                  uint8_t load_slots, uint64_t *out, char *why, size_t whysz)
{
    uint64_t m = 0;

    for (uint8_t k = 0; k < n; k++) {
        bool found = false;
        for (unsigned i = 0; i < f->n_src_regs && i < 64; i++) {
            if (f->src_regs[i] == regs[k]) {
                m |= 1ULL << i;
                found = true;
            }
        }
        if (!found) {
            if (why) {
                g_snprintf(why, whysz, "no slot for %s",
                           generic_reg_name_or_unknown(regs[k]));
            }
            return false;
        }
    }
    /*
     * The load-data slots, for the store-data arm.  The bit positions start
     * at n_src_regs, and a slot beyond max_dep_loads has no bit to set --
     * which is the same disqualifying direction as a register with no slot,
     * so it fails the same way.
     */
    for (unsigned k = 0; k < QDEP_MAX_ACCESS; k++) {
        if (!(load_slots & (1u << k))) {
            continue;
        }
        if (k >= f->max_dep_loads || f->n_src_regs + k >= 64) {
            if (why) {
                g_snprintf(why, whysz, "no slot for LOAD%u (of %u)",
                           k, f->max_dep_loads);
            }
            return false;
        }
        m |= 1ULL << (f->n_src_regs + k);
    }
    *out = m;
    return true;
}

/*
 * The format's own all-inputs default, written out.
 *
 * Reached when the store-data family is refused on an instruction whose
 * HAS_REG flag is set by a refiner: the field is on the wire and something
 * has to be in it, and the only honest something is what a consumer would
 * have assumed had the block been absent -- every src, every load slot, the
 * immediate.  Never the Capstone mask this replaces, and never a short one.
 */
uint64_t all_inputs_mask(const InsnFields *f)
{
    unsigned nsrc = f->n_src_regs;
    unsigned nbits = nsrc + f->max_dep_loads + (f->has_immediate ? 1u : 0u);
    uint64_t m = 0;

    for (unsigned i = 0; i < nbits && i < 64; i++) {
        m |= 1ULL << i;
    }
    return m;
}


/*
 * THE COORDINATE SYSTEM, and why it is rebuilt rather than read.
 *
 * A dependency mask on the wire is a set of BIT POSITIONS, and
 * docs/format.rst fixes what a position means: "bits [0, n_src) depends on
 * src_reg[i]".  So the mask says nothing on its own -- src_regs[] is the
 * dictionary it is read through, and until this function existed that
 * dictionary was built entirely by the Capstone operand walk.  Every
 * register QEMU's emitters named was then LOOKED UP in Capstone's list to
 * find the bit that would carry it.
 *
 * That is a live Capstone route into a QEMU-sourced block, and it was
 * MEASURED rather than argued: under `QEMU_CAP_MUTATE=access`, 88 published
 * address dependencies across x86_64, aarch64 and riscv64 named a DIFFERENT
 * architectural register, because a flipped access flag moved a register
 * out of src_regs[] and every later slot shifted down underneath a mask
 * whose bit positions index it (ARC3_CLOSE.md 1.5).  J3's bar is verbatim
 * "If we are still susceptible to Capstone artifacts, we didn't do it
 * right", so the answer is not to document the coupling but to remove it.
 *
 * WHAT THIS DOES.  Every register QEMU's own emitters named -- the address
 * provenance of each access, then the store datum's -- is seated at the
 * HEAD of src_regs[], in QEMU's order, before anything the operand walk
 * found.  The address mask is then a set of bit positions inside a run that
 * QEMU alone decides the length, the order and the contents of, so its
 * VALUE is a function of QEMU's answer and of nothing else.  Corrupting
 * Capstone's operands can still change what follows the prefix; it cannot
 * reach into it.
 *
 * IT IS A PERMUTATION, NOT A REPLACEMENT.  Nothing is dropped: the walk's
 * sources that QEMU did not name keep their identity and follow the prefix
 * in their original relative order, and a register QEMU named that the walk
 * missed is APPENDED to the instruction's sources rather than being cause
 * to refuse.  Every mask, lane array and register key that indexes a source
 * slot is carried through the same permutation in the same step, so no
 * consumer sees a mask and a dictionary from different orders.
 *
 * WHY HERE AND NOT IN THE WALK.  The refiners write source-slot masks and
 * run between the walk and this file; a reindex before them would be undone
 * by them.  qdep_apply() is the last writer, which is the only place the
 * permutation can be applied once and be final.
 *
 * WHAT IT DOES NOT REACH, stated because a half-closed route reads like a
 * closed one.  n_src_regs is still the walk's COUNT, so the load-data bits
 * at [n_src, n_src + max_dep_loads) and the immediate bit above them still
 * sit at Capstone-decided offsets.  The ADDRESS masks never set those bits
 * -- their layout has no load-data slots and this extractor never sets
 * their immediate -- so the address families are complete.  The STORE-DATA
 * family sets both, and is therefore invariant in its register bits and not
 * in the other two.  See champsim_tracer_qdep.h.
 */
bool reindex_src_for_qemu(InsnFields *f, InsnRegNames *rn,
                          const uint8_t *q, uint8_t nq)
{
    uint8_t neworder[MAX_SRC_REGS];
    uint8_t map[MAX_SRC_REGS];          /* old source slot -> new slot */
    unsigned n = 0;
    const unsigned nsrc_o = f->n_src_regs;
    const unsigned mdl = f->max_dep_loads;

    if (nsrc_o > MAX_SRC_REGS) {
        return false;
    }
    for (uint8_t k = 0; k < nq; k++) {
        if (n >= MAX_SRC_REGS) {
            return false;
        }
        neworder[n++] = q[k];
    }
    for (unsigned i = 0; i < nsrc_o; i++) {
        uint8_t r = f->src_regs[i];
        bool seated = false;

        for (uint8_t k = 0; k < nq; k++) {
            if (q[k] == r) {
                map[i] = k;
                seated = true;
                break;
            }
        }
        if (seated) {
            continue;
        }
        if (n >= MAX_SRC_REGS) {
            return false;
        }
        map[i] = (uint8_t)n;
        neworder[n++] = r;
    }
    const unsigned nsrc_n = n;
    /*
     * The widest bit either layout addresses is the register mask's
     * immediate, one above the load-data run.  Refuse rather than write a
     * mask whose top bit fell off the end of the word.
     */
    if (nsrc_o + mdl >= 64 || nsrc_n + mdl >= 64) {
        return false;
    }
    if (nsrc_n == nsrc_o) {
        bool moved = false;
        for (unsigned i = 0; i < nsrc_o; i++) {
            if (map[i] != i) {
                moved = true;
                break;
            }
        }
        if (!moved) {
            return true;        /* already QEMU's order; nothing to carry */
        }
    }

    /*
     * @nloads is max_dep_loads for a register mask and ZERO for an address
     * mask, which is the whole difference between the two layouts -- and
     * the immediate bit sits one above the run in both.
     */
    auto carry = [&](uint64_t m, unsigned nloads) -> uint64_t {
        uint64_t o = 0;

        for (unsigned i = 0; i < nsrc_o; i++) {
            if (m & (1ULL << i)) {
                o |= 1ULL << map[i];
            }
        }
        for (unsigned k = 0; k < nloads; k++) {
            if (m & (1ULL << (nsrc_o + k))) {
                o |= 1ULL << (nsrc_n + k);
            }
        }
        if (m & (1ULL << (nsrc_o + nloads))) {
            o |= 1ULL << (nsrc_n + nloads);
        }
        return o;
    };

    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] = carry(f->dst_dep_mask[d], mdl);
    }
    for (uint8_t st = 0; st < f->max_dep_stores; st++) {
        f->store_data_dep_mask[st] = carry(f->store_data_dep_mask[st], mdl);
        f->store_addr_dep_mask[st] = carry(f->store_addr_dep_mask[st], 0);
    }
    for (uint8_t l = 0; l < f->max_dep_loads; l++) {
        f->load_addr_dep_mask[l] = carry(f->load_addr_dep_mask[l], 0);
    }

    uint64_t lane[MAX_SRC_REGS];
    const QemuRegKey *keys[MAX_SRC_REGS];
    memset(lane, 0, sizeof(lane));
    memset(keys, 0, sizeof(keys));
    for (unsigned i = 0; i < nsrc_o; i++) {
        lane[map[i]] = f->src_lane_mask[i];
        if (rn && rn->src_qemu_reg_keys) {
            keys[map[i]] = rn->src_qemu_reg_keys[i];
        }
    }
    for (unsigned i = 0; i < nsrc_n; i++) {
        f->src_regs[i] = neworder[i];
        f->src_lane_mask[i] = lane[i];
        if (rn && rn->src_qemu_reg_keys) {
            /*
             * A slot the walk never held has no key to carry, so it is
             * resolved from the generic ID -- the same singleton the walk
             * would have installed.  Without this the register would be on
             * the wire as an identity with no readable value behind it.
             */
            rn->src_qemu_reg_keys[i] =
                keys[i] ? keys[i] : qemu_reg_key_for_generic(neworder[i]);
        }
    }
    f->n_src_regs = (uint8_t)nsrc_n;
    return true;
}

/*
 * The register list QEMU's emitters named for this instruction, in QEMU's
 * own order: every access's address provenance first, in the order the
 * accesses were emitted, then the store datum's.
 *
 * Both halves are included whenever QEMU stated them IN FULL, and the test
 * is q->state / q->data_state as qdep_note_insn() left them -- the RAW
 * per-family verdicts, before qdep_apply()'s shape and multi gates, which
 * are the two places a Capstone-derived count still speaks.  Gating the
 * prefix on those would make its LENGTH a function of Capstone's operand
 * list and put back, one level up, exactly the coupling this removes.
 */
/*
 * Carry a REGISTER-side mask (dst_dep[] / store_data_dep[]) across a change
 * in the LOAD SLOT COUNT.
 *
 * The layout is  [0,nsrc) src | [nsrc, nsrc+nload) load-data | one imm bit
 * (champsim_tracer_mnemonics.h), so resizing the load run moves both bands
 * above the sources.  The src bits are untouched: they index a run this
 * change does not resize.
 *
 * The load band cannot always be carried exactly, and where it cannot the
 * answer is the OVER-approximation, never the short one -- a mask naming
 * fewer inputs than really feed a value tells a consumer it may issue before
 * a producer has landed:
 *
 *   GROWN   a slot the old count did not have is a sub-access of an operand
 *           the old count DID have: `vmovdqu (%rax),%ymm0` is one Capstone
 *           operand and two QEMU loads, and the destination takes both
 *           halves.  So a mask that named any load slot names every new one
 *           too; a mask that named none still names none, because the writer
 *           positively said this value does not come from memory.
 *   SHRUNK  a named slot may have no bit left.  Every remaining slot is set,
 *           and when none remain the memory input cannot be expressed at
 *           all -- *@lost says so and the caller publishes the all-inputs
 *           default rather than a mask that quietly dropped it.
 */
uint64_t carry_load_band(uint64_t m, unsigned nsrc, unsigned old_n,
                         unsigned new_n, bool *lost)
{
    const uint64_t src_bits = nsrc >= 64 ? ~0ULL : ((1ULL << nsrc) - 1);
    uint64_t out = m & src_bits;
    bool named = false;

    *lost = false;
    if (nsrc + new_n >= 64) {
        *lost = true;
        return out;
    }
    for (unsigned k = 0; k < old_n && nsrc + k < 64; k++) {
        if (m & (1ULL << (nsrc + k))) {
            named = true;
            if (k < new_n) {
                out |= 1ULL << (nsrc + k);
            }
        }
    }
    if (named) {
        if (new_n == 0) {
            *lost = true;
        }
        for (unsigned k = 0; k < new_n; k++) {
            out |= 1ULL << (nsrc + k);
        }
    }
    if (nsrc + old_n < 64 && (m & (1ULL << (nsrc + old_n)))) {
        out |= 1ULL << (nsrc + new_n);      /* the immediate bit */
    }
    return out;
}

/*
 * THE SURVIVOR ROWS FOR ONE DECODE IDENTITY, resolved to registers.
 *
 * champsim_tracer_src_survivors.h is a MEASUREMENT re-emitted as a table
 * (tools/gen_src_survivors.py): every register the tracer's per-ISA decode
 * publishes as a source that QEMU's ordered read list does not state, keyed
 * on qemu_plugin_insn_decode_id() because that is the only identity that
 * survives the operand walk's removal.  A row is one of two kinds and the
 * generator picked which from the census, not from a reading:
 *
 *   SRC_SURV_FIXED  the register belongs to the RULE.  `ret` reads SS in
 *                   every encoding of `ret`; an aarch64 FP instruction
 *                   consults the FP-enable gate whichever registers it
 *                   names.  The row carries the generic id.
 *   SRC_SURV_SELF   the register belongs to the INSTANCE.  `movlpd` writes
 *                   one half of an XMM and leaves the other, `mthc1` one
 *                   half of an FPR: the merged-into register is a source
 *                   and it is whichever register the encoding named.  No
 *                   constant can stand for that, so the row names none and
 *                   the register comes from ONE POSITION in @f's own
 *                   destination list -- the position the census recorded
 *                   the survivor at.  Supplying the WHOLE list instead is
 *                   what fabricated REG_VEC0 on aarch64 vector FP, whose
 *                   survivor is REG_FCSR at dst_regs[1].
 *
 * A decode id with NO row contributes nothing, and that is counted
 * (g_src_flip_no_row) rather than passed over: a corpus-derived table is
 * complete for the corpus it was derived from and the count is what says
 * how often an instruction outside it turns up.
 */
uint8_t src_survivor_regs(uint32_t decode_id, const InsnFields *f,
                          uint8_t *out, uint8_t cap)
{
    unsigned isa = (unsigned)trace_isa;
    uint8_t n = 0;

    if (isa >= G_N_ELEMENTS(g_src_survivor_tables)) {
        return 0;
    }
    const SrcSurvivorTable *t = &g_src_survivor_tables[isa];

    if (!t->rows) {
        return 0;
    }
    auto take = [&](uint8_t r) {
        if (r == REG_NONE) {
            return;
        }
        for (uint8_t k = 0; k < n; k++) {
            if (out[k] == r) {
                return;
            }
        }
        if (n < cap) {
            out[n++] = r;
        }
    };
    for (unsigned i = 0; i < t->n; i++) {
        if (t->rows[i].decode_id != decode_id) {
            continue;
        }
        if (t->rows[i].kind == SRC_SURV_SELF) {
            /* One position, not the list.  A row whose position the
             * instance does not have contributes nothing rather than
             * falling back to a neighbour: a register at a different
             * position is a different register. */
            if (t->rows[i].dst_pos < f->n_dst_regs) {
                take(f->dst_regs[t->rows[i].dst_pos]);
            }
        } else {
            take(t->rows[i].reg);
        }
    }
    return n;
}

uint8_t qemu_named_regs(const QDepInsn *q, uint8_t *out,
                        const InsnFields *f, bool dst_ok)
{
    uint8_t n = 0;

    auto take = [&](const uint8_t *regs, uint8_t cnt) {
        for (uint8_t i = 0; i < cnt; i++) {
            bool dup = false;
            for (uint8_t k = 0; k < n; k++) {
                if (out[k] == regs[i]) {
                    dup = true;
                    break;
                }
            }
            if (!dup && n < MAX_SRC_REGS) {
                out[n++] = regs[i];
            }
        }
    };

    if (q->state == QDEP_OK) {
        for (uint8_t a = 0; a < q->n_loads; a++) {
            take(q->load_addr_regs[a], q->n_load_addr_regs[a]);
        }
        for (uint8_t a = 0; a < q->n_stores; a++) {
            take(q->store_addr_regs[a], q->n_store_addr_regs[a]);
        }
    }
    if (q->data_state == QDEP_OK) {
        for (uint8_t a = 0; a < q->n_stores; a++) {
            take(q->store_data_regs[a], q->n_store_data_regs[a]);
        }
    }
    /*
     * The DESTINATION family's inputs, last, and ONLY the rows that will
     * actually be published.  Last rather than first so that an instruction
     * whose destinations name nothing the memory families did not already
     * name keeps the exact prefix -- and therefore the exact bit positions --
     * it had before this family existed.
     *
     * @dst_ok is dst_precheck()'s verdict and @f is the slot list, because a
     * register seated for a destination the WIRE does not have is a source
     * on the wire that no dependency refers to.  See dst_precheck().
     */
    if (dst_ok && f) {
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            for (uint8_t k = 0; k < q->n_dst; k++) {
                if (q->dst_reg[k] == f->dst_regs[d]) {
                    take(q->dst_dep_regs[k], q->n_dst_dep_regs[k]);
                    break;
                }
            }
        }
    }
    /*
     * THE INSTRUCTION'S OWN SOURCE LIST, in QEMU's order, last.
     *
     * The three runs above are PROVENANCE: the registers a particular
     * dependency of this instruction was derived from.  This one is the
     * instruction's read set -- every register QEMU's emitters stated the
     * instruction reads, ordered by qemu_plugin_insn_reg_read_list()'s own
     * ordering contract (qemu-plugin-dataflow.h).  It is what the wire's
     * src_regs[] is FOR, and until this call the wire took it from the
     * Capstone operand walk alone.
     *
     * LAST, for the same reason the destination family is last: a register
     * the provenance runs already named keeps the slot it already had, so
     * every mask this file writes keeps the bit position it had before this
     * run existed.  A read the provenance runs did not name is APPENDED --
     * a source the wire was missing, seated where nothing else moves.
     *
     * Gated on src_state alone.  It is qdep_note_insn()'s RAW verdict for
     * the read list, not the shape or count gates the memory families pass
     * through: those are decided from access lists this run does not read,
     * and gating on them would make the source list's length a function of
     * a question about memory.
     */
    if (q->src_state == QDEP_OK || q->src_state == QDEP_R_SHORT) {
        take(q->src_reg, q->n_src);
    }
    /*
     * AND THE MEMBERS A STATED CONTAINER COVERS (#277), which until now
     * justified a published source without supplying one.
     *
     * #277 settled that a container and its member are one register at two
     * granularities and that the container COVERS the member: mipsel's
     * `bc1t` reads the whole `fcr31` because that is where the condition
     * bit lives, and the wire publishes the FCC the encoding selects.  The
     * census has always read that as JUSTIFIED -- correctly -- but the
     * justification reached the SCORE and not the WIRE: qemu_named_regs()
     * seated src_reg[] alone, so the member arrived on the wire only from
     * the operand walk, and a census reading 0 UNJUSTIFIED said nothing
     * about whether the walk could be removed.  Measured: deleting the
     * walk's read arm took REG_PRED0 and REG_PRED1 off two mipsel `bc1t`
     * program counters whose census rows were green on both arms.
     *
     * This seats the PUBLISHED MEMBER, never the container and never the
     * whole range.  The container is QEMU's statement that the storage is
     * read; which member of it this encoding selects is the wire's own
     * answer, already in @f.  Nothing is invented: a register not published
     * cannot be seated by this run, so the union can only regain a source
     * the wire already carries.
     */
    if ((q->src_state == QDEP_OK || q->src_state == QDEP_R_SHORT) && f) {
        for (uint8_t i = 0; i < f->n_src_regs; i++) {
            for (uint8_t k = 0; k < q->n_src_cont; k++) {
                if (f->src_regs[i] >= q->src_cont_lo[k] &&
                    f->src_regs[i] <= q->src_cont_hi[k]) {
                    take(&f->src_regs[i], 1);
                    break;
                }
            }
        }
    }
    /*
     * THE SURVIVOR ROWS, after the read list.
     *
     * The read list above is every register QEMU STATES the instruction
     * reads.  It is not every register the wire publishes: the census has
     * been measuring the difference all along, and
     * champsim_tracer_src_survivors.h is that difference re-emitted as a
     * table, keyed on the decode identity so it can be looked up without a
     * mnemonic.  Those registers reach the wire today only because the
     * operand walk also runs, and the walk is being deleted.  Seating them
     * HERE is what makes that deletion cost nothing: after it, this call is
     * the only thing that still supplies them.
     *
     * AFTER the read list, never before it.  A survivor is by construction a
     * register QEMU did not state, so it cannot collide with an entry above
     * it, and putting it last keeps every position the read list decided.
     *
     * NOT gated on src_state.  A survivor row is a property of the decode
     * identity, measured and compiled in; it does not become false because
     * this instance's read list was refused.  Gating it on src_state would
     * delete a published register exactly on the instructions whose QEMU
     * statement is weakest, which is the R12.1 direction that is never
     * available.
     */
    {
        uint8_t surv[MAX_SRC_REGS];
        uint8_t ns = src_survivor_regs(q->decode_id, f, surv,
                                       (uint8_t)MAX_SRC_REGS);
        take(surv, ns);
    }
    return n;
}

/*
 * THE SOURCE LIST QEMU STATES, folded to generic words.
 *
 * Read off the ORDERED read list rather than the read BITMAP, because the
 * bitmap is indexed by TCG global and two kinds of source have no global at
 * all: a CPUArchState byte range -- every vector and x87 source on x86, every
 * V register on aarch64 -- and the architectural zero register, which R7.3
 * says is a source the encoding named and not the emulator's to drop.  Scored
 * against the bitmap, `add rd,x0,rs` would report x0 as a source the wire
 * invented and every SSE instruction would report its whole input set that
 * way.  The census would then be measuring this reader, not the wire.
 *
 * ON THE WIRE.  qemu_named_regs() takes this list, so every register QEMU
 * states the instruction reads is seated in src_regs[] -- the census below
 * still scores it, but it is no longer only a measurement.  Kept on QDepInsn
 * rather than computed at the scoring site because the accessors are keyed on
 * (tb, idx) and there is no later moment at which that pair still names
 * anything.
 *
 * A member with no generic word is SKIPPED, not refused, and the instruction
 * stays scorable.  The scoring asks whether a PUBLISHED register is justified;
 * a QEMU source the tracer has no word for cannot justify or refute one, and
 * refusing the instruction on it would hide every other entry's verdict behind
 * a vocabulary gap.
 */
static void note_src(const struct qemu_plugin_tb *tb, size_t idx,
                     QDepInsn *out)
{
    unsigned n = qemu_plugin_insn_reg_read_list(tb, idx, nullptr, 0);
    std::vector<qemu_plugin_dataflow_reg_entry> e;
    unsigned skipped = 0;

    if (n == QEMU_PLUGIN_DF_INCOMPLETE) {
        out->src_state = QDEP_R_NORECORD;
        return;
    }
    if (n == 0) {
        /*
         * An instruction that reads nothing.  A RESULT, not a refusal:
         * QDEP_OK with an empty list says every published source is
         * unjustified, which is the honest reading and the one the census
         * has to be able to reach.
         */
        out->src_state = QDEP_OK;
        return;
    }
    e.resize(n);
    for (unsigned i = 0; i < n; i++) {
        e[i].struct_size = sizeof(e[i]);
    }
    if (qemu_plugin_insn_reg_read_list(tb, idx, e.data(), n) != n) {
        out->src_state = QDEP_R_NORECORD;
        return;
    }

    for (unsigned i = 0; i < n; i++) {
        uint8_t gen = REG_ID_COUNT;

        switch (e[i].kind) {
        case QEMU_PLUGIN_DF_ENT_GLOBAL: {
            if (e[i].reg >= g_nregs) {
                g_src_skip_global.fetch_add(1, std::memory_order_relaxed);
                skipped++;
                continue;
            }
            /*
             * A REPRESENTATION SELECTOR is not struck here, and the reason
             * is the opposite of the one that strikes it on the write side.
             * There it made `ja` an EFLAGS producer, because every
             * instruction that touches the flags writes cc_op.  Here reading
             * cc_op IS reading the flags -- it is how the value is fetched --
             * and it folds to the same generic word the other three cc_
             * globals do, so it adds no register the read did not involve.
             */
            gen = g_gen_of_reg[e[i].reg];
            {
                uint8_t clo = 0, chi = 0;
                const char *cnm = qemu_plugin_dataflow_reg_name(e[i].reg, nullptr,
                                                                nullptr);

                if (src_container_range(cnm, &clo, &chi) &&
                    out->n_src_cont < QDEP_MAX_SRC) {
                    out->src_cont_lo[out->n_src_cont] = clo;
                    out->src_cont_hi[out->n_src_cont] = chi;
                    out->n_src_cont++;
                }
            }
            break;
        }
        case QEMU_PLUGIN_DF_ENT_FIELD: {
            char fnm[64];
            qemu_plugin_dataflow_field fl[kMaxFields];
            unsigned nf = qemu_plugin_insn_fields(tb, idx, nullptr, 0);

            if (nf == QEMU_PLUGIN_DF_INCOMPLETE || nf > kMaxFields ||
                e[i].index >= nf) {
                g_src_skip_field_unnamed.fetch_add(1,
                                                   std::memory_order_relaxed);
                tally(&g_src_skip_sig, "field-list  (no fields[] row)");
                skipped++;
                continue;
            }
            for (unsigned k = 0; k < nf; k++) {
                fl[k].struct_size = sizeof(fl[k]);
            }
            if (qemu_plugin_insn_fields(tb, idx, fl, nf) != nf) {
                g_src_skip_field_unnamed.fetch_add(1,
                                                   std::memory_order_relaxed);
                tally(&g_src_skip_sig, "field-list  (second call short)");
                skipped++;
                continue;
            }
            if (!qemu_plugin_dataflow_field_reg(fl[e[i].index].env_offset,
                                                fl[e[i].index].size,
                                                fnm, sizeof(fnm))) {
                g_src_skip_field_unnamed.fetch_add(1,
                                                   std::memory_order_relaxed);
                {
                    char *k2 = g_strdup_printf(
                        "field-range  off=%u size=%u (no declared regfile)",
                        fl[e[i].index].env_offset, fl[e[i].index].size);
                    tally(&g_src_skip_sig, k2);
                    g_free(k2);
                }
                skipped++;
                continue;
            }
            {
                uint8_t clo = 0, chi = 0;

                if (src_container_range(fnm, &clo, &chi) &&
                    out->n_src_cont < QDEP_MAX_SRC) {
                    out->src_cont_lo[out->n_src_cont] = clo;
                    out->src_cont_hi[out->n_src_cont] = chi;
                    out->n_src_cont++;
                }
            }
            gen = generic_for_field_name(fnm);
            if (gen >= REG_ID_COUNT) {
                g_src_skip_field_generic.fetch_add(1,
                                                   std::memory_order_relaxed);
                {
                    char *k2 = g_strdup_printf("field-word   %s", fnm);
                    tally(&g_src_skip_sig, k2);
                    g_free(k2);
                }
                skipped++;
                continue;
            }
            break;
        }
        case QEMU_PLUGIN_DF_ENT_ZERO:
            gen = REG_ZERO;
            break;
        case QEMU_PLUGIN_DF_ENT_NAME: {
            /*
             * A source QEMU states by NAME because it has neither a TCG
             * global nor a CPUArchState range -- an AArch64 ARM_CP_CONST
             * system register, read out of the ARMCPU object at translation
             * time.  The name is in the same namespace a DISCARDED
             * DESTINATION's is, so it takes the same route to a generic
             * word: the QEMU-indexed table first, then the non-architectural
             * fold, exactly as generic_for_field_name() does for a range.
             */
            qemu_plugin_dataflow_named_read nr[kMaxNamedReads];
            unsigned nn = qemu_plugin_insn_named_reads(tb, idx, nullptr, 0);

            if (nn == QEMU_PLUGIN_DF_INCOMPLETE || nn > kMaxNamedReads ||
                e[i].index >= nn) {
                g_src_skip_other.fetch_add(1, std::memory_order_relaxed);
                tally(&g_src_skip_sig, "name-list   (no named_reads[] row)");
                skipped++;
                continue;
            }
            for (unsigned k = 0; k < nn; k++) {
                nr[k].struct_size = sizeof(nr[k]);
            }
            if (qemu_plugin_insn_named_reads(tb, idx, nr, nn) != nn) {
                g_src_skip_other.fetch_add(1, std::memory_order_relaxed);
                tally(&g_src_skip_sig, "name-list   (second call short)");
                skipped++;
                continue;
            }
            {
                const char *nm = nr[e[i].index].reg;

                gen = nm ? generic_for_qemu_name(nm) : REG_ID_COUNT;
                if (gen >= REG_ID_COUNT && nm) {
                    gen = fold_nonarch(nm);
                }
                if (gen >= REG_ID_COUNT) {
                    g_src_skip_other.fetch_add(1, std::memory_order_relaxed);
                    {
                        char *k2 = g_strdup_printf("name-word    %s",
                                                   nm ? nm : "?");
                        tally(&g_src_skip_sig, k2);
                        g_free(k2);
                    }
                    skipped++;
                    continue;
                }
            }
            break;
        }
        default:
            g_src_skip_other.fetch_add(1, std::memory_order_relaxed);
            tally(&g_src_skip_sig, "kind         (unknown entry kind)");
            skipped++;
            continue;
        }
        if (gen >= REG_ID_COUNT) {
            const char *nm = qemu_plugin_dataflow_reg_name(e[i].reg,
                                                           nullptr, nullptr);
            const char *low = nm ? nonarch_lowering_reason(trace_isa, nm)
                                 : nullptr;
            char *k2;

            if (low) {
                g_src_skip_lowering.fetch_add(1, std::memory_order_relaxed);
                k2 = g_strdup_printf("lowering     %s -- %s", nm, low);
            } else {
                g_src_skip_global.fetch_add(1, std::memory_order_relaxed);
                k2 = g_strdup_printf("global-word  %s", nm ? nm : "?");
            }
            tally(&g_src_skip_sig, k2);
            g_free(k2);
            skipped++;
            continue;
        }
        {
            uint8_t k;

            for (k = 0; k < out->n_src; k++) {
                if (out->src_reg[k] == gen) {
                    break;
                }
            }
            if (k < out->n_src) {
                continue;
            }
            if (out->n_src >= QDEP_MAX_SRC) {
                /*
                 * Over the fold's bound.  REFUSED, because a short source
                 * list scored against the wire reports a real source as
                 * unjustified and puts a coverage row on a list that has no
                 * defect in it.  The census's third outcome exists for
                 * exactly this.
                 */
                out->src_state = QDEP_R_WIDE;
                out->n_src = 0;
                g_src_wide.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            out->src_reg[out->n_src++] = gen;
        }
    }
    if (skipped) {
        g_src_skip_insns.fetch_add(1, std::memory_order_relaxed);
    }
    out->src_state = QDEP_OK;
}

/*
 * THE DESTINATION FAMILY, read off the writes QEMU's emitters stated.
 *
 * `writes[]` carries, per TCG global this instruction defines, the set the
 * value came from -- the same provenance namespace the address and store-data
 * arms fold, so the same fold_prov() reads it and the same rules decide what
 * it may not say.  Two things are different and both are deliberate:
 *
 *   THE LOAD BAND IS OPEN.  @load_slots is non-NULL, because a destination
 *   genuinely may be a value this same instruction loaded -- that is what
 *   every load instruction is -- and the HAS_REG layout has a bit per load
 *   slot to carry it.  An ADDRESS mask has no such bits and refuses there.
 *
 *   THE ROWS ARE GENERIC, NOT GLOBAL.  Several globals stand for one
 *   architectural register: x86 lowers the flags onto cc_op, cc_dst, cc_src
 *   and cc_src2, and the wire has ONE destination slot for REG_FLAGS.  Its
 *   dependency set is the UNION over the globals that make it up, which is
 *   the only fold that cannot be short -- taking any one of them would drop
 *   the inputs the others carry.
 *
 * A written global with no generic word is SKIPPED and tallied, not refused.
 * It has no name in the tracer's vocabulary, so it cannot equal any
 * `dst_regs[d]`, so no mask is ever written for it.  What DOES decide the
 * family is the slot side, and that is decided in qdep_apply() where
 * `dst_regs[]` exists: a wire destination with no row here refuses the whole
 * instruction rather than leaving one slot to be filled from the answer this
 * flip replaces.
 */
void note_dst(const struct qemu_plugin_tb *tb, size_t idx, QDepInsn *out,
              const uint8_t *load_ord, unsigned n_memops)
{
    const unsigned nw = (g_nregs + 63) / 64;
    std::vector<uint64_t> wr(nw ? nw : 1);
    unsigned got;

    if (g_nregs == 0) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }
    got = qemu_plugin_insn_reg_writes(tb, idx, wr.data(), nw);
    if (got == QEMU_PLUGIN_DF_INCOMPLETE || got != nw) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }

    std::vector<uint64_t> w(g_prov_words);
    for (unsigned r = 0; r < g_nregs; r++) {
        uint8_t gen, k;
        uint8_t memop_slots = 0;
        uint8_t sregs[QDEP_MAX_ADDR_REGS];
        uint8_t sn = 0, simm = 0;
        QDepState rc;

        if (!(wr[r / 64] & (1ULL << (r % 64)))) {
            continue;
        }
        /*
         * A REPRESENTATION SELECTOR is not a register fact (#265).  QEMU
         * declared it -- x86's cc_op, which says WHICH function computes
         * EFLAGS from cc_dst/cc_src/cc_src2 and holds no part of the value.
         * Every instruction that touches the flags for any reason writes it,
         * including the ones that only READ them, so counting it as a
         * destination made `ja` an EFLAGS producer.  R10.1's category
         * reached from the register side.
         */
        if (g_reg_is_selector[r]) {
            g_dst_repr_selector.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        gen = g_gen_of_reg[r];
        if (gen >= REG_ID_COUNT) {
            const char *nm =
                qemu_plugin_dataflow_reg_name(r, nullptr, nullptr);
            tally(&g_dst_unmapped_name, nm ? nm : "?");
            continue;
        }
        if (qemu_plugin_insn_write_prov(tb, idx, r, w.data(),
                                        g_prov_words) != g_prov_words) {
            out->dst_state = QDEP_R_NORECORD;
            return;
        }
        /*
         * FOLD FIRST, SEAT SECOND.  The row used to be created before the
         * provenance was read, which cannot express "this write turned out
         * not to be one": a destination whose every write is a change of
         * representation has no row at all, and creating it first would
         * leave an empty one behind that the wire comparison then reports as
         * a register QEMU wrote and the wire does not carry.
         */
        rc = fold_prov(w.data(), sregs, &sn, &memop_slots, &simm);
        if (rc != QDEP_OK) {
            out->dst_state = rc;
            return;
        }
        /*
         * AND THE ONE SHAPE THE FOLD CANNOT SEE.  `clc` materialises the
         * flags and then clears CF with a translator constant: two writes to
         * cc_src, whose provenances union to the materialisation's own, and
         * the second one is an architectural flag write.  QEMU's emitter
         * says so (insn_dataflow_note_supplied_value) and the statement wins
         * over the shape, because a shape that cannot see a fact must not
         * overrule an emitter that states it.
         */
        if (!qemu_plugin_insn_write_supplies_value(tb, idx, r) &&
            is_repr_change(gen, sregs, sn, memop_slots, simm)) {
            g_dst_repr_change.fetch_add(1, std::memory_order_relaxed);
            tally(&g_dst_repr_sig, generic_reg_name_or_unknown(gen));
            if (out->n_repr_only < QDEP_MAX_DST) {
                bool seen = false;
                for (uint8_t z = 0; z < out->n_repr_only; z++) {
                    seen |= (out->repr_only[z] == gen);
                }
                if (!seen) {
                    out->repr_only[out->n_repr_only++] = gen;
                }
            }
            continue;
        }
        for (k = 0; k < out->n_dst; k++) {
            if (out->dst_reg[k] == gen) {
                break;
            }
        }
        if (k == out->n_dst) {
            if (out->n_dst >= QDEP_MAX_DST) {
                out->dst_state = QDEP_R_WIDE;
                return;
            }
            out->dst_reg[out->n_dst++] = gen;
        }
        for (uint8_t z = 0; z < sn; z++) {
            if (!add_reg(out->dst_dep_regs[k], &out->n_dst_dep_regs[k],
                         sregs[z])) {
                out->dst_state = QDEP_R_WIDE;
                return;
            }
        }
        out->dst_dep_imm[k] |= simm;
        /*
         * MEMOP ordinals into LOAD ordinals, exactly as the store-data
         * arm does it and for the same reason: QEMU numbers the load-data
         * provenance bits by position in the WHOLE access list and the
         * wire's load-data band is indexed by position among the LOADS.
         */
        for (unsigned m = 0; m < QDEP_MAX_ACCESS; m++) {
            if (!(memop_slots & (1u << m))) {
                continue;
            }
            if (m >= n_memops || load_ord[m] == 0xFF) {
                out->dst_state = QDEP_R_UNREPRESENTABLE;
                return;
            }
            out->dst_dep_load_slots[k] |= (uint8_t)(1u << load_ord[m]);
        }
    }

    /*
     * THE WRITES THAT ARE NOT GLOBALS (#226).
     *
     * A vector register is written by a store into CPUArchState, not by a
     * write to a TCG global, so the loop above sees nothing at all for
     * `movdqa %xmm1,%xmm2` -- and the wire's destination list, which does
     * name REG_VEC2, then had no row to match and refused the whole family
     * (QDEP_R_DST_UNNAMED).  The env fields carry the same two facts a
     * global write does, the register and where its value came from, so
     * they go through the same union.
     *
     * A field whose range has no name, or a name with no generic word, is
     * SKIPPED and tallied exactly as an unmapped global is: it cannot equal
     * any dst_regs[d], so no mask is ever written for it, and the wire slot
     * that wanted it refuses one gate later where the slot list exists.
     */
    unsigned nf = qemu_plugin_insn_fields(tb, idx, nullptr, 0);

    if (nf == QEMU_PLUGIN_DF_INCOMPLETE) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }
    if (nf > kMaxFields) {
        out->dst_state = QDEP_R_WIDE;
        return;
    }
    if (nf) {
        qemu_plugin_dataflow_field fl[kMaxFields];

        for (unsigned i = 0; i < nf; i++) {
            fl[i].struct_size = sizeof(fl[i]);
        }
        if (qemu_plugin_insn_fields(tb, idx, fl, nf) != nf) {
            out->dst_state = QDEP_R_NORECORD;
            return;
        }
        for (unsigned i = 0; i < nf; i++) {
            char fnm[64];
            uint8_t gen, k;
            uint8_t memop_slots = 0;
            QDepState rc;

            if (!(fl[i].dir & QEMU_PLUGIN_DF_WR)) {
                continue;
            }
            if (!qemu_plugin_dataflow_field_reg(fl[i].env_offset, fl[i].size,
                                                fnm, sizeof(fnm))) {
                tally_field_off(&g_field_unnamed, fl[i].env_offset);
                continue;
            }
            /*
             * R7.7's category, reached by the field route rather than the
             * global one: the reservation monitor is a product of the
             * emulation and is deliberately given no generic word.  Skipped
             * like any other write with no word, and tallied where the
             * globals' monitor writes are so the category stays one number.
             */
            if (is_monitor_value(fnm)) {
                tally(&g_monitor_name, fnm);
                continue;
            }
            gen = generic_for_field_name(fnm);
            if (gen >= REG_ID_COUNT) {
                tally(&g_field_unmapped_name, fnm);
                continue;
            }
            for (k = 0; k < out->n_dst; k++) {
                if (out->dst_reg[k] == gen) {
                    break;
                }
            }
            if (k == out->n_dst) {
                if (out->n_dst >= QDEP_MAX_DST) {
                    out->dst_state = QDEP_R_WIDE;
                    return;
                }
                out->dst_reg[out->n_dst++] = gen;
            }
            if (qemu_plugin_insn_field_prov(tb, idx, i, w.data(),
                                            g_prov_words) != g_prov_words) {
                out->dst_state = QDEP_R_NORECORD;
                return;
            }
            rc = fold_prov(w.data(), out->dst_dep_regs[k],
                           &out->n_dst_dep_regs[k], &memop_slots,
                           &out->dst_dep_imm[k]);
            if (rc == QDEP_OK) {
                for (unsigned m = 0; m < QDEP_MAX_ACCESS; m++) {
                    if (!(memop_slots & (1u << m))) {
                        continue;
                    }
                    if (m >= n_memops || load_ord[m] == 0xFF) {
                        rc = QDEP_R_UNREPRESENTABLE;
                        break;
                    }
                    out->dst_dep_load_slots[k] |= (uint8_t)(1u << load_ord[m]);
                }
            }
            if (rc != QDEP_OK) {
                out->dst_state = rc;
                return;
            }
        }
    }

    /*
     * THE WRITES THE EMULATOR THREW AWAY (#260).
     *
     * A register with no TCG global and no CPUArchState storage appears in
     * neither loop above, because both are indexed by a place the value
     * lives and this value lives nowhere.  AArch64's `cmp x0,x1` IS
     * `subs xzr,x0,x1`; MIPS' `mul` leaves HI and LO architecturally
     * UNPREDICTABLE; `move $zero,$ra` translates to no op at all.  The wire
     * carries all three as destinations and, until QEMU's emitters stated
     * them, they were the whole of the #218 droppable population -- a
     * register the ISA says the instruction writes with no QEMU row to
     * match, which refused the family and, at the flip, would have deleted
     * a real destination.
     *
     * Read exactly like a field: name to generic word, provenance through
     * the same fold, unioned onto the same row if some other route already
     * created one.  A name with no generic word is SKIPPED and tallied,
     * because it cannot equal any dst_regs[d] and so no mask is ever
     * written for it.
     */
    unsigned nd = qemu_plugin_insn_discards(tb, idx, nullptr, 0);

    if (nd == QEMU_PLUGIN_DF_INCOMPLETE) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }
    if (nd > kMaxDiscards) {
        out->dst_state = QDEP_R_WIDE;
        return;
    }
    if (nd) {
        qemu_plugin_dataflow_discard dc[kMaxDiscards];

        for (unsigned i = 0; i < nd; i++) {
            dc[i].struct_size = sizeof(dc[i]);
        }
        if (qemu_plugin_insn_discards(tb, idx, dc, nd) != nd) {
            out->dst_state = QDEP_R_NORECORD;
            return;
        }
        for (unsigned i = 0; i < nd; i++) {
            uint8_t gen, k;
            uint8_t memop_slots = 0;
            QDepState rc;

            if (dc[i].zero_reg) {
                /*
                 * The architectural ZERO register, resolved the way a
                 * zero-register SOURCE already is (fold_prov's
                 * qemu_plugin_dataflow_prov_zero_reg arm): by QEMU saying
                 * which register it is, not by a name in a table.  It has
                 * none -- AArch64's XZR is not in the GDB namespace and a
                 * synthetic row for it would put a register that cannot be
                 * read into the namespace values are read from.
                 */
                gen = (uint8_t)REG_ZERO;
            } else if (!dc[i].reg) {
                tally(&g_discard_unmapped_name, "?");
                continue;
            } else {
                gen = generic_for_qemu_name(dc[i].reg);
                if (gen >= REG_ID_COUNT) {
                    tally(&g_discard_unmapped_name, dc[i].reg);
                    continue;
                }
            }
            if (dc[i].by_index) {
                g_indexed_write_rows.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_discard_rows.fetch_add(1, std::memory_order_relaxed);
            }
            for (k = 0; k < out->n_dst; k++) {
                if (out->dst_reg[k] == gen) {
                    break;
                }
            }
            if (k == out->n_dst) {
                if (out->n_dst >= QDEP_MAX_DST) {
                    out->dst_state = QDEP_R_WIDE;
                    return;
                }
                out->dst_reg[out->n_dst++] = gen;
            }
            if (qemu_plugin_insn_discard_prov(tb, idx, i, w.data(),
                                              g_prov_words) != g_prov_words) {
                out->dst_state = QDEP_R_NORECORD;
                return;
            }
            rc = fold_prov(w.data(), out->dst_dep_regs[k],
                           &out->n_dst_dep_regs[k], &memop_slots,
                           &out->dst_dep_imm[k]);
            if (rc == QDEP_OK) {
                for (unsigned m = 0; m < QDEP_MAX_ACCESS; m++) {
                    if (!(memop_slots & (1u << m))) {
                        continue;
                    }
                    if (m >= n_memops || load_ord[m] == 0xFF) {
                        rc = QDEP_R_UNREPRESENTABLE;
                        break;
                    }
                    out->dst_dep_load_slots[k] |= (uint8_t)(1u << load_ord[m]);
                }
            }
            if (rc != QDEP_OK) {
                out->dst_state = rc;
                return;
            }
        }
    }
    out->dst_state = QDEP_OK;
}

/*
 * Publish the destination family, or say why it was not published.
 *
 * The matching runs HERE and not in note_dst() because it needs
 * `dst_regs[]`, which does not exist until the template builder has run the
 * operand walk.  What is matched is a GENERIC register on both sides: the
 * wire's destination slot d names dst_regs[d], and QEMU's rows name the
 * register each write folded to, so slot d takes the row for the same
 * register no matter what ORDER either side enumerated in.  There is no
 * k-th-of-one-is-k-th-of-the-other assumption to make.
 *
 * THE WHOLE FAMILY REFUSES ON ONE UNMATCHED SLOT.  A wire destination QEMU
 * named only as a CPUArchState byte range -- x86's XMM and x87 files,
 * aarch64's V registers -- has no row here (#218).  Filling the slots that
 * DID match and leaving that one as the refiner left it would publish a
 * block whose entries come from two sources, which is worse than either
 * source alone: nothing downstream can tell which entry is which.
 *
 * AND A REFUSED FAMILY KEEPS WHAT THE REFINER WROTE.  Not the all-inputs
 * default -- that is a WIDENING of a published mask, and widening the
 * remainder is a separate decision that belongs with the numbers for it,
 * not with this flip.  The surviving population is counted by cause and by
 * mnemonic so the size of the decision is a measurement.
 */
/*
 * WILL the destination family be written, and if not, why.
 *
 * Split out from the writing because the answer is needed BEFORE the source
 * index is rebuilt.  qemu_named_regs() seats every register a published mask
 * could name at the head of src_regs[], and seating one for a family that
 * then publishes nothing puts a register on the wire that no dependency
 * refers to.  That is not hypothetical: the first draft seated the PC write's
 * provenance on every aarch64 `br x17`, whose wire destination list is EMPTY,
 * and 1,786 instructions gained a REG_PC source with nothing pointing at it.
 * The validator's static_reg_sets check failed on 11 of them, which is the
 * gate doing its job -- and the reason this predicate exists.
 *
 * Every test here reads q, f->dst_regs[] and the two flags; none reads a bit
 * position, so all of it is decidable before the permutation.  The one check
 * that is NOT here is regs_to_mask()'s, and it cannot fail after the prefix
 * is seated: the prefix is exactly the set of registers those masks name.
 */
unsigned dst_precheck(const InsnFields *f, const QDepInsn *q,
                      char *why, size_t whysz)
{
    unsigned st = q->dst_state;

    if (f->n_dst_regs == 0) {
        return QDEP_NONE;       /* no slot: no dst_dep[] array to write */
    }
    if (f->n_dst_regs > MAX_DST_REGS) {
        return QDEP_R_WIDE;
    }
    if (st != QDEP_OK) {
        return st;
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        uint8_t k;

        for (k = 0; k < q->n_dst; k++) {
            if (q->dst_reg[k] == f->dst_regs[d]) {
                break;
            }
        }
        if (k == q->n_dst) {
            /*
             * THE LAZY-FLAG INTERPRETATION'S ONE LOSS DIRECTION, named
             * before it is refused (#265).  A register the wire DOES carry
             * as a destination, whose every stated write this file struck as
             * a change of representation, has had the only thing that could
             * fill its slot taken away.  Refusing the family is the honest
             * outcome -- the block keeps the answer the refiner wrote, and
             * nothing short is published -- but it is a LOSS and so it is
             * counted separately from a register QEMU simply never
             * mentioned, and tallied by mnemonic so the class is a list.
             *
             * The shape that would land here is `stc`/`clc`/`cmc`:
             * materialise the flags, then set one bit with a translator
             * constant, which arrives with the same provenance the
             * materialisation had.  Its coverage path is a QEMU-side note at
             * those emitters saying the write SUPPLIES a value, the same
             * shape #205 and #230 used.  It has no subject in the corpus.
             */
            for (uint8_t z = 0; z < q->n_repr_only; z++) {
                if (q->repr_only[z] != f->dst_regs[d]) {
                    continue;
                }
                g_dst_repr_refused.fetch_add(1, std::memory_order_relaxed);
                tally(&g_dst_repr_refused_sig,
                      generic_reg_name_or_unknown(f->dst_regs[d]));
                break;
            }
            g_snprintf(why, whysz, "no QEMU write row for %s",
                       generic_reg_name_or_unknown(f->dst_regs[d]));
            return QDEP_R_DST_UNNAMED;
        }
        /*
         * A DESTINATION IN ITS OWN PROVENANCE IS NOW A DECISION AND NOT A
         * DILEMMA, and this is where the old refusal stood.
         *
         * The two shapes it could not separate are separated at the emitter
         * now.  An in-place LOWERING -- riscv64's `flw fa0,0(a6)` loading
         * straight into cpu_fpr[rd] and NaN-boxing it there -- reads back a
         * value THIS instruction produced, and df_written_prov() forwards
         * that write's own provenance instead of naming the register, so the
         * self-reference never arrives.  A narrow WRITEBACK -- `setne %al`,
         * `mtc1` -- reads the register only to carry the bits it does not
         * write, and insn_dataflow_note_preserve_read() says so at the
         * writeback, so that read contributes nothing (R7.1: a register is a
         * source when the INSTRUCTION takes it as one).
         *
         * What is left is the genuine accumulate: `add %rax,%rbx`, `push`
         * and `pop` on RSP, `movk` on Xd, `lwl`/`lwr` merging into their
         * destination, `cmovcc` preserving it on a false condition.  Every
         * one of those is an edge a renaming regfile must respect (R7), and
         * R3 forbids eliding a dependency because it looks redundant -- the
         * tracer records it and a downstream simulator decides what to do
         * with it.  So it PUBLISHES, and it is counted so the population is
         * visible rather than assumed.
         */
        for (uint8_t z = 0; z < q->n_dst_dep_regs[k]; z++) {
            if (q->dst_dep_regs[k][z] == q->dst_reg[k]) {
                g_dst_accum.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
        /*
         * THE CONSTANT GATE, split into the two shapes it used to report as
         * one.  A destination's provenance can be empty for three reasons and
         * they do NOT have one answer, which is why one refusal covering all
         * three could never be discharged:
         *
         *   the value is the instruction's own ENCODING -- the empty-and-
         *   complete reading the address and store-data families already run
         *   under, and the template has an immediate slot to point at;
         *
         *   the source operand was the architectural ZERO REGISTER, which
         *   reaches this set as a provenance BIT (INSN_DF_ZERO_PROV_BIT) now
         *   that insn_dataflow_note_zero_reg() is anchored to the writing
         *   instruction -- so such a row is no longer empty and does not
         *   arrive here at all;
         *
         *   a constant that is neither, which nothing here can name.
         *
         * The first two publish.  Only the third refuses, and it is counted
         * under its own state so its size is a number rather than a residue.
         */
        if (q->n_dst_dep_regs[k] == 0 && q->dst_dep_load_slots[k] == 0) {
            /*
             * AND THE ENCODING IS NOT ALWAYS A CANDIDATE.  The empty-and-
             * complete reading says "the value came from the instruction's
             * own encoding" because nothing else is left -- but on an
             * instruction whose encoded field the ARCHITECTURE does not
             * define as a dataflow operand, that reading names a source the
             * machine does not have.  MIPS `teq rs,zero,0x7` published
             * `dst_dep = IMM` on this route: the claim that the exception
             * state it writes depends on the trap code, which QEMU never
             * materialises and the ISA never feeds to anything (R2 --
             * architectural dependencies, and this is not one).
             *
             * The decoder's NON_DATAFLOW statement removes the encoding from
             * the candidates, and what is left is genuinely empty: a
             * constant this file cannot name, which is the third shape
             * below and refuses under its own state.
             */
            if (!f->has_immediate ||
                (q->imm_non_dataflow && !q->imm_reached)) {
                g_snprintf(why, whysz, "empty set for %s",
                           generic_reg_name_or_unknown(q->dst_reg[k]));
                return QDEP_R_DST_UNSTATED_CONST;
            }
            /*
             * The encoding.  apply_dst() writes the immediate bit for this
             * slot; nothing is refused for it.
             */
        } else if (f->has_immediate) {
            /*
             * The destination named registers AND the instruction carries an
             * immediate.  The encoding is an ADDITIONAL candidate source
             * beside the registers QEMU named, and no reading of "empty and
             * complete" reaches it -- which is why this was a flat refusal
             * until the ENCODED-IMMEDIATE PROVENANCE BIT existed (#248).
             *
             * Neither of the two rules that suggest themselves survives its
             * counter-example.  A blanket bit is refuted by `ldr x0,[x1,#8]`:
             * that destination's value came from the LOAD, and the #8 is the
             * ADDRESS's, already carried in load_addr_dep[] -- setting the
             * bit here would put the address's arithmetic into the data mask,
             * the one conflation the separate provenances exist to prevent.
             * And "it depends on the immediate unless there is a load" is
             * refuted by `add $5,(%rax)`, whose FLAGS destination does depend
             * on the 5.
             *
             * The BIT decides it, because it is a fact rather than a rule:
             * the decoder that materialised the encoding's immediate said so,
             * and the bit travelled the same dataflow every other provenance
             * bit travels.  Where it arrived is the answer, in both
             * directions.
             */
            if (q->dst_dep_imm[k]) {
                /*
                 * The encoding reached this destination.  Nothing is refused;
                 * apply_dst() adds the immediate bit to this slot's mask.
                 */
            } else if (q->imm_stated && q->imm_reached) {
                /*
                 * The decoder stated the immediate, the value it named was
                 * read by an op of this instruction, and it did not arrive
                 * here.  The register-only mask IS complete: this is the
                 * `ldr x0,[x1,#8]` case, and the #8 is in the address mask
                 * where a consumer that wants it will find it.
                 */
            } else if (q->imm_non_dataflow) {
                /*
                 * THE THIRD VERDICT (#252).  The decoder stated that the
                 * field the encoding carries is one the ARCHITECTURE does
                 * not define as a dataflow operand, so the bit did not fail
                 * to arrive -- it was never going to.  MIPS' trap and break
                 * codes are the class: the exception's Cause.ExcCode is
                 * fixed by the OPCODE and the code is left in the
                 * instruction word for software to read, so nothing this
                 * instruction writes depends on it.
                 *
                 * The register-only mask IS complete, and this is not the
                 * folded case below: there the encoding WOULD have fed the
                 * value and the emulator optimised it away, which R7.3
                 * forbids publishing as the machine's; here the machine
                 * itself never gave the field a path.  Opposite facts, so
                 * opposite answers, and the count says how many rows the
                 * distinction is worth.
                 */
                g_dst_imm_non_dataflow.fetch_add(1, std::memory_order_relaxed);
            } else if (q->imm_stated) {
                /*
                 * Stated, but QEMU folded the value away before any op read
                 * it -- `addi rd,rs,0` lowers to a move.  The bit had nowhere
                 * to travel, so its absence is the emulator's optimisation
                 * and not the machine's, which R7.3 forbids publishing.
                 */
                g_snprintf(why, whysz, "immediate folded before any op");
                return QDEP_R_DST_IMM_FOLDED;
            } else {
                /*
                 * No decoder on this instruction's path states its encoded
                 * immediate yet.  The absence of the bit means nobody looked.
                 * Refused, and counted per mnemonic so the coverage hole is a
                 * LIST of decoder paths rather than an adjective.
                 */
                g_snprintf(why, whysz, "no decoder stated this immediate");
                return QDEP_R_DST_IMM_UNSTATED_PATH;
            }
        }
    }
    /*
     * THE GATE THAT STOOD HERE IS DELETED (R12).  It read
     * `if (!f->has_reg_deps) return QDEP_NO_BLOCK;` -- the refiner's answer,
     * asked before QEMU's was known, and it discarded a destination
     * provenance this function had just proved complete on 15,763 rows
     * across four ISAs.  Whether the block exists is decided at the end of
     * qdep_apply() from what QEMU stated; this function's job is only to say
     * whether QEMU stated it.  QDEP_NO_BLOCK survives as the must-be-0 that
     * catches the inversion coming back.
     */
    return QDEP_OK;
}

static bool qdep_mutate_is(const char *want)
{
    static const char *mode;
    static bool read;

    if (!read) {
        mode = getenv("QEMU_DF_MUTATE");
        read = true;
    }
    return mode && !strcmp(mode, want);
}

/*
 * Move a published destination mask, without changing what it can express.
 *
 * The immediate bit is the one slot every layout has -- it sits above the
 * source registers and the load-data band, so it exists whatever the
 * template's shape -- and flipping it moves the mask's VALUE and its
 * resolved NAME set together.  Non-emptiness is preserved in both
 * directions because emptiness is a decision made elsewhere and must not
 * be made here: an empty mask is how the encoding rule is spelled, and a
 * mask that exists at all is what dep_publish() decided from the refiner's
 * answer.  A mutation that emptied or filled one would move rows by moving
 * a gate rather than a mask, and the movement would not be this family's.
 */
static uint64_t qdep_move_mask(const InsnFields *f, uint64_t m)
{
    unsigned imm = (unsigned)f->n_src_regs + f->max_dep_loads;
    uint64_t b;

    if (m == 0 || imm >= 63) {
        return m;
    }
    b = 1ULL << imm;
    return (m == b) ? (m | 1ULL) : (m ^ b);
}

/*
 * Publish the destination family, or say why it was not published.
 *
 * The matching runs HERE and not in note_dst() because it needs
 * `dst_regs[]`, which does not exist until the template builder has run the
 * operand walk.  What is matched is a GENERIC register on both sides: the
 * wire's destination slot d names dst_regs[d], and QEMU's rows name the
 * register each write folded to, so slot d takes the row for the same
 * register no matter what ORDER either side enumerated in.  There is no
 * k-th-of-one-is-k-th-of-the-other assumption to make.
 *
 * THE WHOLE FAMILY REFUSES ON ONE UNMATCHED SLOT.  A wire destination QEMU
 * named only as a CPUArchState byte range -- x86's XMM and x87 files,
 * aarch64's V registers -- has no row here (#218).  Filling the slots that
 * DID match and leaving that one as the refiner left it would publish a
 * block whose entries come from two sources, which is worse than either
 * source alone: nothing downstream can tell which entry is which.
 *
 * AND A REFUSED FAMILY KEEPS WHAT THE REFINER WROTE.  Not the all-inputs
 * default -- that is a WIDENING of a published mask, and widening the
 * remainder is a separate decision that belongs with the numbers for it,
 * not with this flip.  The surviving population is counted by cause and by
 * mnemonic so the size of the decision is a measurement.
 */
/*
 * THE DESTINATION LIST, RE-SEATED INTO QEMU'S ORDER (#232).
 *
 * `dst_regs[]` is the dictionary every destination-family field is read
 * through -- docs/format.rst fixes slot d as naming dst_reg[d] -- and until
 * this function existed that dictionary was the Capstone operand walk's
 * entire answer: which register a slot is for, and how many slots exist.
 * The masks could be QEMU's to the last bit and a flipped access flag would
 * still move which register they were about.  Witnessed rather than
 * inferred: riscv64 `c.mv` at 0x103ba, bytes `ae84` -- corrupt the operand
 * access flags and the wire's destination becomes x11 where QEMU says x9.
 *
 * IT IS A PERMUTATION, AND THAT IS A MEASUREMENT AND NOT A CHOICE.  Both
 * directions of the two lists' disagreement now read ZERO on all four ISAs:
 * dst_precheck() refuses the family when the wire names a destination QEMU
 * has no write row for (the #218 droppable leg, 4 -> 0 once FEAT_MOPS'
 * syndrome registers were stated at their emitter), and the mirror -- QEMU
 * naming a destination the wire's list lacks -- is the must-be-0 census row
 * and it is 0.  So for a family that reaches here the two lists are the same
 * SET, and seating QEMU's order over it drops nothing and invents nothing.
 *
 * THE SET IS CHECKED RATHER THAN ASSUMED.  If the two ever differ this
 * refuses the RE-SEATING for that instruction and counts it: the list stays
 * the walk's, the masks below still publish (they match by REGISTER, not by
 * slot), and the disagreement is a number instead of a silently truncated
 * or silently grown destination list.
 *
 * REG_PC IS THE ONE REGISTER THE WALK STILL DECIDES, and it is named rather
 * than hidden.  QEMU charges a translation block's final pc write to
 * whichever instruction the block ended on -- a delay-slot `lw`, a
 * page-final `mov` -- so QEMU's write list carries REG_PC on instructions
 * the ISA does not define as writing it, and R10.1 rules that artefact off
 * the wire.  Nothing in QEMU's statements separates that write from a
 * branch's architectural one, so the separation is taken from whether the
 * wire's list already carries REG_PC.  That is a surviving operand-walk
 * input, on exactly one register, and its coverage path is #261/R10: a
 * QEMU-side statement distinguishing the block's pc write from the
 * instruction's would retire it.
 *
 * Everything indexed by a destination slot moves in the same step --
 * dst_dep_mask[], dst_lane_mask[] and the reg-snapshot keys -- so no
 * consumer ever sees a mask, a lane set and a dictionary from two orders.
 */
static bool reseat_dst_for_qemu(InsnFields *f, InsnRegNames *rn,
                                const QDepInsn *q)
{
    uint8_t neworder[MAX_DST_REGS];
    uint8_t from[MAX_DST_REGS];         /* new slot -> old slot */
    unsigned n = 0;
    const unsigned ndst = f->n_dst_regs;
    bool wire_has_pc = false;

    if (ndst > MAX_DST_REGS) {
        return false;
    }
    for (uint8_t d = 0; d < ndst; d++) {
        if (f->dst_regs[d] == REG_PC) {
            wire_has_pc = true;
        }
    }
    for (uint8_t k = 0; k < q->n_dst; k++) {
        uint8_t r = q->dst_reg[k];
        uint8_t d;

        if (r == REG_PC && !wire_has_pc) {
            continue;               /* the BLOCK's pc write -- R10.1 */
        }
        for (d = 0; d < ndst; d++) {
            if (f->dst_regs[d] == r) {
                break;
            }
        }
        if (d == ndst) {
            return false;           /* QEMU names one the wire lacks */
        }
        if (n >= MAX_DST_REGS) {
            return false;
        }
        from[n] = d;
        neworder[n++] = r;
    }
    if (n != ndst) {
        return false;               /* the wire names one QEMU lacks */
    }
    {
        bool moved = false;

        for (unsigned d = 0; d < ndst; d++) {
            if (from[d] != d) {
                moved = true;
                break;
            }
        }
        if (!moved) {
            return true;            /* already QEMU's order */
        }
    }
    {
        uint64_t dep[MAX_DST_REGS], lane[MAX_DST_REGS];
        const QemuRegKey *keys[MAX_DST_REGS];
        const bool have_keys = rn && rn->dst_qemu_reg_keys;

        for (unsigned d = 0; d < ndst; d++) {
            dep[d]  = f->dst_dep_mask[from[d]];
            lane[d] = f->dst_lane_mask[from[d]];
            if (have_keys) {
                keys[d] = rn->dst_qemu_reg_keys[from[d]];
            }
        }
        for (unsigned d = 0; d < ndst; d++) {
            f->dst_regs[d]      = neworder[d];
            f->dst_dep_mask[d]  = dep[d];
            f->dst_lane_mask[d] = lane[d];
            if (have_keys) {
                rn->dst_qemu_reg_keys[d] = keys[d];
            }
        }
    }
    return true;
}

/*
 * THE PER-PC SOURCE WITNESS.  See the call site in apply_dst() for why a
 * tally cannot answer the question this answers.
 *
 * One line per instruction whose source list is decided, TSV, columns:
 *
 *   pc  decode_id  rule  mnemonic  src_state  wstate
 *   PUB=<published src_regs[]>          the wire's list, post-reindex
 *   QN=<qemu_named_regs()>              what the list becomes once the
 *                                       operand walk's read arm is gone
 *   SURV=<survivor rows for this id>    the compiled-in table's answer
 *   RD=<QEMU's ordered read list>       what the emulator states
 *   CONT=<container ranges>             #277's justification ranges
 *
 * The file is opened once, appended to under a lock, and closed by the
 * process exit; a run that sets the variable to a path it cannot open gets
 * no witness and no silent success -- the failure is recorded in the
 * sidecar by the report, because a witness that cannot find its subject
 * must FAIL rather than print nothing.
 */
std::atomic<int> g_src_pc_dump_state{0};     /* 0 unasked, 1 open, 2 failed */
FILE *g_src_pc_dump = nullptr;
std::mutex g_src_pc_dump_lock;
std::atomic<uint64_t> g_src_pc_dump_rows{0};

/*
 * THE MECHANISM CORPUS'S STAGING SLOT.
 *
 * dump_src_mech_row() is called from create_tb_template(), which is the only
 * level that holds the ENCODING BYTES -- the dependency model is handed
 * fields, never the instruction.  The MECHANISM columns are the opposite:
 * they live on QDepInsn and on two derived lists (qemu_named_regs(), the
 * survivor rows) that only qdep_apply() is positioned to compute, and one of
 * their inputs -- dst_precheck()'s verdict -- exists nowhere else at all.
 *
 * So the answer is staged here, by the same statement that writes the per-pc
 * witness, and read one call later by the encoding-keyed writer.  The two
 * calls are adjacent for one instruction on one thread: create_tb_template()
 * runs qdep_apply() and then the dump calls, per instruction, in a loop.
 * `pc` is carried and re-checked at the read so a slot filled for one
 * instruction can never be written under another one's encoding -- a
 * mismatch is DROPPED and counted, never printed, because a mechanism row
 * attributed to the wrong encoding is worse than a missing one.
 *
 * FILLED ONLY WHEN THE CORPUS IS LIVE.  With CST_SRC_MECH_DUMP unset this
 * whole block is one relaxed load: qemu_named_regs() and src_survivor_regs()
 * are not walked, and the translation path pays nothing for an instrument
 * nobody asked for.
 */

struct SrcMechStage {
    bool        valid;
    uint64_t    pc;
    uint32_t    decode_id;
    const char *rule;
    uint8_t     src_state;
    uint8_t     srcx_state;
    uint8_t     status_flags;
    uint8_t     wstate;
    uint8_t     n_qn;
    uint8_t     qn[MAX_SRC_REGS];
    uint8_t     n_sv;
    uint8_t     sv[MAX_SRC_REGS];
    uint8_t     n_rd;
    uint8_t     rd[QDEP_MAX_SRC];
    uint8_t     n_rdx;
    uint8_t     rdx[QDEP_MAX_SRC];
    uint8_t     n_cont;
    uint8_t     cont_lo[QDEP_MAX_SRC];
    uint8_t     cont_hi[QDEP_MAX_SRC];
    /* The translation's SHAPE, and QEMU's write side.  See QDepInsn. */
    uint8_t     x_have_shape;
    uint8_t     x_calls;
    uint8_t     x_noreturn_calls;
    uint8_t     x_mem_reads;
    uint8_t     x_mem_writes;
    uint8_t     n_wr;
    uint8_t     wr[QDEP_MAX_DST];
};
static thread_local SrcMechStage g_mech_stage;
std::atomic<uint64_t> g_mech_stage_mismatch{0};

void reglist_str(GString *g, const uint8_t *regs, uint8_t n)
{
    for (uint8_t i = 0; i < n; i++) {
        g_string_append_printf(g, "%s%s", i ? "," : "",
                               generic_reg_name_or_unknown(regs[i]));
    }
    if (!n) {
        g_string_append(g, "-");
    }
}

void dump_src_pc_row(const InsnFields *f, const QDepInsn *q,
                     const char *mnem, unsigned wstate)
{
    int st = g_src_pc_dump_state.load(std::memory_order_relaxed);

    if (st == 2) {
        return;
    }
    if (st == 0) {
        std::lock_guard<std::mutex> lk(g_src_pc_dump_lock);
        if (g_src_pc_dump_state.load(std::memory_order_relaxed) == 0) {
            const char *path = getenv("CST_SRC_PC_DUMP");

            if (!path) {
                g_src_pc_dump_state.store(2, std::memory_order_relaxed);
                return;
            }
            g_src_pc_dump = fopen(path, "w");
            if (!g_src_pc_dump) {
                g_src_pc_dump_state.store(2, std::memory_order_relaxed);
                return;
            }
            fprintf(g_src_pc_dump,
                    "#pc\tdecode_id\trule\tmnem\tsrc_state\twstate\tPUB\tQN"
                    "\tSURV\tRD\tSTATUS\tRDX\tCONT\n");
            g_src_pc_dump_state.store(1, std::memory_order_relaxed);
        }
    }
    if (g_src_pc_dump_state.load(std::memory_order_relaxed) != 1) {
        return;
    }

    uint8_t qn[MAX_SRC_REGS];
    uint8_t nq = qemu_named_regs(q, qn, f, wstate == QDEP_OK);
    uint8_t sv[MAX_SRC_REGS];
    uint8_t ns = src_survivor_regs(q->decode_id, f, sv, (uint8_t)MAX_SRC_REGS);

    GString *g = g_string_new(nullptr);
    g_string_append_printf(g, "0x%" PRIx64 "\t%08x\t%s\t%s\t%s\t%s\t",
                           q->insn_vaddr, q->decode_id,
                           q->decode_name ? q->decode_name : "?",
                           mnem ? mnem : "?",
                           state_name(q->src_state), state_name(wstate));
    reglist_str(g, f->src_regs, f->n_src_regs);
    g_string_append_c(g, '\t');
    reglist_str(g, qn, nq);
    g_string_append_c(g, '\t');
    reglist_str(g, sv, ns);
    g_string_append_c(g, '\t');
    reglist_str(g, q->src_reg, q->n_src);
    g_string_append_c(g, '\t');
    g_string_append_printf(g, "%s%s%s%s%s%s",
                           q->status_flags & 0x01 ? "memops_truncated," : "",
                           q->status_flags & 0x02 ? "memops_unnoted," : "",
                           q->status_flags & 0x04 ? "fields_truncated," : "",
                           q->status_flags & 0x08 ? "writes_truncated," : "",
                           q->status_flags & 0x10 ? "prov_truncated," : "",
                           q->status_flags & 0x20 ? "helper_unbounded," : "");
    if (!q->status_flags) {
        g_string_append(g, "-");
    }
    g_string_append_c(g, '\t');
    g_string_append_printf(g, "%s:", state_name(q->srcx_state));
    reglist_str(g, q->srcx, q->n_srcx);
    g_string_append_c(g, '\t');
    for (uint8_t k = 0; k < q->n_src_cont; k++) {
        /*
         * TWO CALLS, TWO STATEMENTS, and that is the whole point.
         *
         * generic_reg_name_or_unknown() answers a BANK register out of one
         * `static __thread char buf[24]`, so two calls in one argument list
         * alias: both %s print whichever call the compiler evaluated last.
         * This site printed the container's LOW bound twice, and what it
         * therefore said about x86 `fxam` was
         *
         *     CONT=REG_FPR0..REG_FPR0
         *
         * -- a SINGLETON container, i.e. "QEMU stated a read of exactly
         * REG_FPR0".  The container is `fpregs`, REG_FPR0..REG_FPR7, the
         * whole x87 register file: QEMU stated that the FILE is read and
         * said nothing about WHICH entry.  Those two readings have opposite
         * consequences for the source-list flip -- a singleton can simply be
         * seated on the wire, a bank cannot, because which member the
         * encoding selects is not in QEMU's statement -- and a reader
         * chasing the wrong-path FPR0 losses is led by this column straight
         * to the wrong one.
         *
         * The aliasing is a property of the callee's buffer, so the fix is
         * at the call: the low bound is copied out before the high bound is
         * asked for.  This is the only multi-call argument list in the
         * plugin (swept, all TUs), and a name the function does not have a
         * word for is NULL, which is printed as such rather than as the
         * other bound.
         */
        const char *lo = generic_reg_name_or_unknown(q->src_cont_lo[k]);
        char lo_buf[24];

        g_strlcpy(lo_buf, lo ? lo : "(unnamed)", sizeof(lo_buf));
        {
            const char *hi = generic_reg_name_or_unknown(q->src_cont_hi[k]);

            g_string_append_printf(g, "%s%s..%s", k ? "," : "", lo_buf,
                                   hi ? hi : "(unnamed)");
        }
    }
    if (!q->n_src_cont) {
        g_string_append(g, "-");
    }
    g_string_append_c(g, '\n');
    {
        std::lock_guard<std::mutex> lk(g_src_pc_dump_lock);
        fputs(g->str, g_src_pc_dump);
    }
    g_src_pc_dump_rows.fetch_add(1, std::memory_order_relaxed);
    g_string_free(g, TRUE);
}

bool apply_dst(InsnFields *f, InsnRegNames *rn, const QDepInsn *q,
               const char *mnem, unsigned wstate, const char *why)
{
    /*
     * The two lists' disagreement, counted in the direction dst_precheck()
     * cannot see: a register QEMU named that the wire's list does not carry.
     * It is the input to the re-seating below -- a non-zero here is exactly
     * what makes the permutation impossible -- so it is counted before it is
     * used, and split so R10.1's block-final pc write is never mistaken for
     * a destination the wire is missing.
     */
    /*
     * THE COLLISION WITNESS, and it is DELIBERATELY OUTSIDE the read-list
     * gate below.
     *
     * What it measures: a decode id that appears with two mnemonics is one
     * rule carrying more than one instruction, and a survivor table keyed on
     * that id alone would give one of them the other's sources.  That is a
     * fact about the DECODE IDENTITY, and the decode identity exists whether
     * or not QEMU stated the instruction's read list.
     *
     * IT USED TO SIT INSIDE `if (q->src_state == QDEP_OK)`, which is the
     * gate on a DIFFERENT list, and the block's own header said it ran "over
     * the WHOLE scored population".  It did not: every instruction whose
     * read list QEMU refused was reached, counted in the tier totals, and
     * silently absent from this list.  Measured on the constructed x87
     * fixture (PASS 34, verify34/FDIVS_WITNESS.txt), the omitted row was
     * `fdivs` -- decode id 0x3764970a, the exact row a reader chasing the
     * x87 identities goes looking for -- and on the libc cell the list ran
     * 14 rows short of its own population.  A census that names its subject
     * as "the whole population" and quietly drops part of it is the standing
     * failure mode of this tree, so the fix is the position, not the prose.
     *
     * The completeness of this list is now ENFORCED, not asserted:
     * @g_src_ident_witness_reached counts every row this site is reached
     * for, the report prints it beside the sum of the printed counts, and
     * their difference is a must-be-0.  See the report block and
     * witness_completeness_selftest().
     */
    {
        char *key = g_strdup_printf("%08x %-26s %s", q->decode_id,
                                    q->decode_name ? q->decode_name : "?",
                                    mnem ? mnem : "?");
        tally(&g_src_ident_witness, key);
        g_free(key);
        g_src_ident_witness_reached.fetch_add(1, std::memory_order_relaxed);
    }
    /*
     * THE PER-PC WITNESS DUMP, env-gated (CST_SRC_PC_DUMP=<path>).
     *
     * WHY A PER-PC DUMP AND NOT A TALLY.  Every source-side census in this
     * file is a TALLY keyed on the decode identity, and a tally answers
     * "which rules" but never "which instruction".  When the operand walk's
     * read arm was deleted as a measurement excursion, 33 program counters
     * lost a published source and not one of them could be named from a
     * tally: the rows the deletion took off the wire sat in the NOT-SCORED
     * population, which no identity-keyed list here reaches.  Adjudicating
     * a row per program counter needs the program counter, so this writes
     * one line per instruction the wire's source list is decided for:
     *
     *   pc  decode_id  decode_rule  mnemonic  src_state  |  published  |
     *   qemu_named_regs (what the source list would be with the operand
     *   walk's read arm gone)  |  survivor rows for this identity  |
     *   QEMU's ordered read list  |  the container ranges (#277)
     *
     * OUTSIDE the read-list gate, for the same reason the collision witness
     * above is: the question is about the decode identity, which exists
     * whether or not QEMU stated a read list, and a witness that skips the
     * refused instructions is blind to exactly the population that needed
     * witnessing.
     *
     * MEASUREMENT ONLY and OFF unless asked for: no wire field is written
     * here, and with the variable unset the site is a single relaxed load.
     */
    dump_src_pc_row(f, q, mnem, wstate);
    /*
     * AND STAGE THE SAME ANSWER FOR THE PER-ENCODING MECHANISM CORPUS,
     * which is written one call later from the level that holds the
     * encoding bytes.  See SrcMechStage.
     */
    if (src_mech_corpus_live()) {
        SrcMechStage *m = &g_mech_stage;

        m->valid        = true;
        m->pc           = q->insn_vaddr;
        m->decode_id    = q->decode_id;
        m->rule         = q->decode_name;
        m->src_state    = q->src_state;
        m->srcx_state   = q->srcx_state;
        m->status_flags = q->status_flags;
        m->wstate       = (uint8_t)wstate;
        m->n_qn = qemu_named_regs(q, m->qn, f, wstate == QDEP_OK);
        m->n_sv = src_survivor_regs(q->decode_id, f, m->sv,
                                    (uint8_t)MAX_SRC_REGS);
        m->n_rd = q->n_src;
        memcpy(m->rd, q->src_reg, q->n_src);
        m->n_rdx = q->n_srcx;
        memcpy(m->rdx, q->srcx, q->n_srcx);
        m->n_cont = q->n_src_cont;
        memcpy(m->cont_lo, q->src_cont_lo, q->n_src_cont);
        memcpy(m->cont_hi, q->src_cont_hi, q->n_src_cont);
        m->x_have_shape     = q->x_have_shape;
        m->x_calls          = q->x_calls;
        m->x_noreturn_calls = q->x_noreturn_calls;
        m->x_mem_reads      = q->x_mem_reads;
        m->x_mem_writes     = q->x_mem_writes;
        /*
         * QEMU's WRITE side, by generic name.  It is the other half of the
         * body-versus-trap join: an enable check writes the exception state
         * and the program counter and nothing architectural, while an
         * instruction QEMU translated the body of names its destinations.
         * Empty where the destination family refused -- which the shape
         * counts above let a reader tell apart from "wrote nothing".
         */
        m->n_wr = q->n_dst;
        memcpy(m->wr, q->dst_reg, q->n_dst);
    }
    /*
     * THE SURVIVOR-ROW REFUTATION, and it runs OUTSIDE the read-list gate
     * below for the same reason the witness above does: the claim under
     * test is about the DECODE RULE, which exists whether or not QEMU
     * stated a complete read list, and the population that most needs
     * testing is exactly the one a `src_state == QDEP_OK` gate skips.  The
     * fourteen SVE encodings exec81 measured as fabricating are all in it.
     *
     * See g_surv_ref_stated for why the JOIN of the tallies is the finding
     * and no single tally is one.
     */
    {
        uint8_t sv[MAX_SRC_REGS];
        uint8_t nsv = src_survivor_regs(q->decode_id, f, sv,
                                        (uint8_t)MAX_SRC_REGS);

        for (uint8_t k = 0; k < nsv; k++) {
            bool stated = false;

            for (uint8_t j = 0; j < q->n_src; j++) {
                if (q->src_reg[j] == sv[k]) {
                    stated = true;
                    break;
                }
            }
            /* The composed-register reading (#277), the same direction the
             * justification test runs it in: a container QEMU states carries
             * its member, so a survivor register inside one is STATED. */
            for (uint8_t j = 0; !stated && j < q->n_src_cont; j++) {
                if (sv[k] >= q->src_cont_lo[j] && sv[k] <= q->src_cont_hi[j]) {
                    stated = true;
                }
            }
            /*
             * Keyed on (decode id, rule, register) and NOT on the mnemonic:
             * the claim is about the RULE, and a key carrying the mnemonic
             * would split one rule's instances into buckets that can never
             * join.
             */
            char *rkey = g_strdup_printf(
                "%08x %-26s %s", q->decode_id,
                q->decode_name ? q->decode_name : "?",
                generic_reg_name_or_unknown(sv[k]));

            if (stated) {
                g_surv_ref_stated.fetch_add(1, std::memory_order_relaxed);
                tally(&g_surv_ref_stated_sig, rkey);
            } else {
                g_surv_ref_silent.fetch_add(1, std::memory_order_relaxed);
                tally(&g_surv_ref_silent_sig, rkey);
                /*
                 * A silent instance whose read list QEMU did not state in
                 * full is WEAKER evidence -- the register could be missing
                 * from the shortfall rather than from the encoding -- so it
                 * is counted apart and printed on the row.  Folding the two
                 * would let a short list masquerade as a fabrication, and
                 * separating them costs one counter.
                 */
                if (q->src_state != QDEP_OK) {
                    tally(&g_surv_ref_short_sig, rkey);
                }
            }
            g_free(rkey);
        }
    }
    /*
     * THE SOURCE-SIDE MEMBERSHIP CENSUS (the unmeasured half).
     *
     * Per PUBLISHED source entry: did QEMU state a read that justifies it?
     * Nothing here writes anything -- `src_regs[]` is still the operand
     * walk's and this change does not move it.  What it does is stop the
     * source half being carried as fine because nobody had looked.
     *
     * Three outcomes, kept apart on purpose.  JUSTIFIED and UNJUSTIFIED
     * partition the entries of instructions whose read list QEMU gave us;
     * NOSTATE counts the entries of the instructions where it did not, and
     * folding those into unjustified would blame the wire for QEMU's own
     * refusal -- the shape that made the destination side's first numbers a
     * 219x overstatement (#231).
     */
    if (q->src_state == QDEP_OK) {
        g_src_insn_scored.fetch_add(1, std::memory_order_relaxed);
        for (uint8_t i = 0; i < f->n_src_regs; i++) {
            bool justified = false;

            for (uint8_t k = 0; k < q->n_src; k++) {
                if (q->src_reg[k] == f->src_regs[i]) {
                    justified = true;
                    break;
                }
            }
            /*
             * AND THE COMPOSED-REGISTER READING (#277): a published MEMBER
             * is justified by QEMU stating the CONTAINER it lives in.  See
             * src_container_range() for the table and for why this direction
             * is the only one the rule runs in.
             */
            for (uint8_t k = 0; !justified && k < q->n_src_cont; k++) {
                if (f->src_regs[i] >= q->src_cont_lo[k] &&
                    f->src_regs[i] <= q->src_cont_hi[k]) {
                    justified = true;
                }
            }
            if (justified) {
                g_src_justified.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            g_src_unjustified.fetch_add(1, std::memory_order_relaxed);
            {
                char *key = g_strdup_printf("%-10s %s", mnem ? mnem : "?",
                                            generic_reg_name_or_unknown(
                                                f->src_regs[i]));
                tally(&g_src_unjustified_sig, key);
                g_free(key);
            }
            /*
             * The same row, keyed the way a flip would have to look it up.
             * The mnemonic is APPENDED as an annotation and is not part of
             * the key's meaning -- it is there so a reader can tell what the
             * rule is, and so a second mnemonic under one id is visible.
             */
            {
                /*
                 * THE ROLE COLUMN, and it is a measurement rather than a
                 * label.  A survivor is reachable from the decode identity
                 * in one of exactly two ways and the census says which:
                 *
                 *  FIXED  the register is a property of the RULE -- `ret`
                 *         reads SS, an aarch64 FP instruction reads the
                 *         FP-enable gate -- so the same register is right
                 *         for every instruction the rule decodes.
                 *  SELF@p the register is a property of the INSTANCE -- a
                 *         partial write merging into whichever register the
                 *         encoding named -- so no constant can stand for it
                 *         and it has to be read from the instruction's own
                 *         destination list, AT THE POSITION p PRINTED HERE.
                 *
                 * The test is whether the SAME instruction publishes this
                 * register as a DESTINATION.  gen_src_survivors.py reads
                 * this column; nothing chooses the kind by hand.
                 *
                 * THE POSITION IS PART OF THE ROLE, and it is why the column
                 * is not the bare word SELF it used to be.  "Also a
                 * destination" is not "varies per instance": an aarch64
                 * `fadd v0.2d,v1.2d,v2.2d` publishes REG_FCSR as BOTH a
                 * source and a destination, so it scored SELF, and a row
                 * that then supplied the instance's WHOLE destination list
                 * handed REG_VEC0 to a wire that never published it -- 8
                 * fabricated registers on the golden net, measured.  With
                 * the position, FADD_v's survivor is dst_regs[1] and is
                 * REG_FCSR on every instance, while INS_general's is
                 * dst_regs[0] and travels with the encoding: both exact,
                 * and neither supplies a register the instruction does not
                 * have in that slot.
                 */
                bool self = false;
                uint8_t self_pos = 0;

                for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                    if (f->dst_regs[d] == f->src_regs[i]) {
                        self = true;
                        self_pos = d;
                        break;
                    }
                }
                char *role = self ? g_strdup_printf("SELF@%u", self_pos)
                                  : g_strdup("FIXED");
                char *key = g_strdup_printf(
                    "%08x %-26s %-14s %-7s %s", q->decode_id,
                    q->decode_name ? q->decode_name : "?",
                    generic_reg_name_or_unknown(f->src_regs[i]),
                    role,
                    mnem ? mnem : "?");
                g_free(role);
                tally(&g_src_survivor_ident, key);
                g_free(key);
            }
        }
        /*
         * And the OTHER direction, counted and never added to the one above.
         * A register QEMU reads that the wire does not publish is a
         * different question with a different answer -- it is what the flip
         * would GAIN, not what it would have to justify -- and one number
         * covering both would be readable as neither.
         */
        for (uint8_t k = 0; k < q->n_src; k++) {
            bool on_wire = false;

            for (uint8_t i = 0; i < f->n_src_regs; i++) {
                if (f->src_regs[i] == q->src_reg[k]) {
                    on_wire = true;
                    break;
                }
            }
            if (!on_wire) {
                g_src_qemu_extra.fetch_add(1, std::memory_order_relaxed);
                char *key = g_strdup_printf("%-10s %s", mnem ? mnem : "?",
                                            generic_reg_name_or_unknown(
                                                q->src_reg[k]));
                tally(&g_src_qemu_extra_sig, key);
                g_free(key);
            }
        }
        /*
         * THE FLIP'S COST, both directions, against the survivor table.
         * See g_src_flip_missing's comment for what the two columns mean
         * and why they are never netted.  Measurement only.
         */
        {
            uint8_t surv[MAX_SRC_REGS];
            uint8_t ns = src_survivor_regs(q->decode_id, f, surv,
                                           (uint8_t)MAX_SRC_REGS);
            auto in_union = [&](uint8_t r) {
                for (uint8_t k = 0; k < q->n_src; k++) {
                    if (q->src_reg[k] == r) {
                        return true;
                    }
                }
                /* The composed-register reading, #277 -- same rule as the
                 * justification test above, because the flip publishes
                 * QEMU's read list and a container in that list carries its
                 * member's dependency by construction. */
                for (uint8_t k = 0; k < q->n_src_cont; k++) {
                    if (r >= q->src_cont_lo[k] && r <= q->src_cont_hi[k]) {
                        return true;
                    }
                }
                for (uint8_t k = 0; k < ns; k++) {
                    if (surv[k] == r) {
                        return true;
                    }
                }
                return false;
            };
            g_src_flip_scored.fetch_add(1, std::memory_order_relaxed);
            if (!ns) {
                g_src_flip_no_row.fetch_add(1, std::memory_order_relaxed);
            }
            for (uint8_t i = 0; i < f->n_src_regs; i++) {
                if (in_union(f->src_regs[i])) {
                    continue;
                }
                /*
                 * THE ADJUDICATION LEDGER FIRST, and it is a redirection
                 * rather than an exemption: the row is still counted, still
                 * printed with its decode id and register, and an OWED row
                 * still blocks the flip -- it is counted in a column that
                 * says WHY it is there.  See g_src_adj_ledger for the rows,
                 * their states and the ruling each closed under.
                 */
                const SrcAdjRow *adj = src_adj_row(
                    q->decode_id, mnem, f->src_regs[i]);
                if (adj) {
                    bool ruled = adj->state == SRC_ADJ_R16;
                    char *okey = g_strdup_printf(
                        "%08x %-26s %-14s %-10s %s %s", q->decode_id,
                        q->decode_name ? q->decode_name : "?",
                        generic_reg_name_or_unknown(f->src_regs[i]),
                        mnem ? mnem : "?", ruled ? "R16:" : "Q:", adj->text);
                    if (ruled) {
                        g_src_adj_r16_n.fetch_add(1,
                                                  std::memory_order_relaxed);
                        tally(&g_src_adj_r16_sig, okey);
                    } else {
                        g_src_adj_owed_n.fetch_add(1,
                                                   std::memory_order_relaxed);
                        tally(&g_src_adj_owed_sig, okey);
                    }
                    g_free(okey);
                    continue;
                }
                g_src_flip_missing.fetch_add(1, std::memory_order_relaxed);
                char *key = g_strdup_printf(
                    "%08x %-26s %-14s %s", q->decode_id,
                    q->decode_name ? q->decode_name : "?",
                    generic_reg_name_or_unknown(f->src_regs[i]),
                    mnem ? mnem : "?");
                tally(&g_src_flip_missing_sig, key);
                g_free(key);
            }
            for (uint8_t k = 0; k < ns; k++) {
                bool on_wire = false;

                for (uint8_t i = 0; i < f->n_src_regs; i++) {
                    if (f->src_regs[i] == surv[k]) {
                        on_wire = true;
                        break;
                    }
                }
                if (on_wire) {
                    continue;
                }
                g_src_flip_extra.fetch_add(1, std::memory_order_relaxed);
                char *key = g_strdup_printf(
                    "%08x %-26s %-14s %s", q->decode_id,
                    q->decode_name ? q->decode_name : "?",
                    generic_reg_name_or_unknown(surv[k]),
                    mnem ? mnem : "?");
                tally(&g_src_flip_extra_sig, key);
                g_free(key);
            }
        }
    } else {
        g_src_insn_nostate.fetch_add(1, std::memory_order_relaxed);
        g_src_nostate.fetch_add(f->n_src_regs, std::memory_order_relaxed);
        /*
         * The rows, keyed exactly as the scored survivors are.  A register
         * this instruction publishes that QEMU's (short or withheld) read
         * list does not carry is a register the flip has to get from
         * somewhere, and the somewhere is a survivor row.  Members already
         * in the list are skipped so the two tables never double-count the
         * same register, and the ROLE is measured the same way -- see the
         * scored arm for why the POSITION is part of it.
         */
        for (uint8_t i = 0; i < f->n_src_regs; i++) {
            bool have = false;

            for (uint8_t k = 0; k < q->n_src; k++) {
                if (q->src_reg[k] == f->src_regs[i]) {
                    have = true;
                    break;
                }
            }
            for (uint8_t k = 0; !have && k < q->n_src_cont; k++) {
                if (f->src_regs[i] >= q->src_cont_lo[k] &&
                    f->src_regs[i] <= q->src_cont_hi[k]) {
                    have = true;
                }
            }
            if (have) {
                continue;
            }
            bool self = false;
            uint8_t self_pos = 0;

            for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                if (f->dst_regs[d] == f->src_regs[i]) {
                    self = true;
                    self_pos = d;
                    break;
                }
            }
            char *role = self ? g_strdup_printf("SELF@%u", self_pos)
                              : g_strdup("FIXED");
            char *key = g_strdup_printf(
                "%08x %-26s %-14s %-7s %s", q->decode_id,
                q->decode_name ? q->decode_name : "?",
                generic_reg_name_or_unknown(f->src_regs[i]),
                role,
                mnem ? mnem : "?");
            g_free(role);
            tally(&g_src_nostate_ident, key);
            g_free(key);
        }
    }

    /*
     * THE WRITE-SIDE REFUSAL RETURNS HERE, AFTER THE SOURCE CENSUS, AND THAT
     * POSITION IS THE POINT (#327/#328).
     *
     * It used to be the first statement of this function.  The write state
     * says nothing about the READ list -- QEMU can refuse to state what an
     * instruction WROTE and still state exactly what it READ -- so returning
     * on it before the source census ran censored the source census by a
     * fact about a different list.  What that produced was not a small
     * error: it was a ZERO ABOUT A POPULATION THE CENSUS NEVER LOOKED AT,
     * and the arc's own gates were drawn from it.  Measured on the golden
     * net at the moment the return moved, the population the census could
     * suddenly see carried 60 fabricated x86_64 registers and 14 x86_64
     * losses that every reading before it had scored 0.
     *
     * The consequence to expect, and it is NOT a defect: NOT-SCORED is now
     * HONESTLY NON-ZERO.  It counts published sources on instructions whose
     * read list QEMU withheld, which is a real third outcome and always was.
     * It is not a must-be-0 row -- it carries no "MUST BE 0" text and
     * must0_scan.py does not score it -- and a reader who calls its non-zero
     * red is reading the pre-hoist censored zero back in.
     */
    if (wstate != QDEP_OK) {
        if (wstate != QDEP_NONE) {
            note_refusal(mnem, wstate, "dst  ", why);
        }
        g_wstate[wstate].fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    for (uint8_t k = 0; k < q->n_dst; k++) {
        bool on_wire = false;

        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            if (f->dst_regs[d] == q->dst_reg[k]) {
                on_wire = true;
                break;
            }
        }
        if (on_wire) {
            continue;
        }
        if (q->dst_reg[k] == REG_PC) {
            g_dst_wire_missing_pc.fetch_add(1, std::memory_order_relaxed);
        } else {
            char *key = g_strdup_printf("%-10s %s", mnem ? mnem : "?",
                                        generic_reg_name_or_unknown(
                                            q->dst_reg[k]));
            tally(&g_dst_wire_missing, key);
            g_free(key);
            g_dst_wire_missing_other.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (reseat_dst_for_qemu(f, rn, q)) {
        g_dst_reseated.fetch_add(1, std::memory_order_relaxed);
    } else {
        /*
         * The two lists are not the same set, so no permutation of one is
         * the other.  The list stays the walk's and the masks below still
         * publish -- they are matched by REGISTER and not by slot, so every
         * slot that does exist still gets QEMU's answer -- and the row is
         * counted, because a destination list this file could not seat is
         * the one place the operand walk still decides the wire's
         * dictionary.  It reads 0 on all four ISAs today.
         */
        g_dst_reseat_refused.fetch_add(1, std::memory_order_relaxed);
        tally(&g_dst_reseat_refused_sig, mnem ? mnem : "?");
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        uint8_t k;
        uint64_t m = 0;
        char w2[64] = "";

        for (k = 0; k < q->n_dst; k++) {
            if (q->dst_reg[k] == f->dst_regs[d]) {
                break;
            }
        }
        if (k == q->n_dst ||
            !regs_to_mask(f, q->dst_dep_regs[k], q->n_dst_dep_regs[k],
                          q->dst_dep_load_slots[k], &m, w2, sizeof(w2))) {
            /*
             * Unreachable by construction -- the prefix seated exactly these
             * registers -- so it is a REFUSAL and not a fallback: publishing
             * the slots that did resolve would leave the rest carrying the
             * answer this flip replaces, and the block would come from two
             * sources at once.
             */
            note_refusal(mnem, QDEP_R_UNREPRESENTABLE, "dst  ", w2);
            g_wstate[QDEP_R_UNREPRESENTABLE]
                .fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if (m == 0) {
            /*
             * THE ENCODING.  The provenance is empty and it is COMPLETE --
             * every way it could have been short is a refusal in
             * dst_precheck() -- so the value came from the one place a
             * provenance made of registers and env ranges cannot name: the
             * instruction's own encoding.  dst_precheck() has already refused
             * the case with no immediate slot to point at, so reaching here
             * means the bit exists.
             *
             * The same rule 4a104e0be4 settled for the address families and
             * fb92a61ea4 for store data, under #230's condition -- it fires
             * only where NO NOTE NAMES A REGISTER.  A folded register and the
             * architectural zero register both arrive as provenance bits, so
             * a row whose encoding does name a register has a non-empty mask
             * and never reaches this line.  A shape that ought to carry a
             * note appearing in this count means the note is not reaching the
             * write, never that the rule needs an exception.
             */
            m = 1ULL << (f->n_src_regs + f->max_dep_loads);
            g_dst_imm.fetch_add(1, std::memory_order_relaxed);
        } else if (f->has_immediate) {
            /*
             * THE ENCODING BESIDE REGISTERS (#248).  The mask is not empty,
             * so the "empty and complete" reading above cannot reach this
             * slot -- but the instruction carries an immediate, and whether
             * that immediate is one of THIS destination's sources is a
             * question the register names cannot settle.
             *
             * The encoded-immediate provenance bit settles it, and
             * dst_precheck() has already refused every row where it could
             * not: a row reaching here either carries the bit or was proven
             * not to, so both branches are decisions and neither is a
             * default.
             */
            if (q->dst_dep_imm[k]) {
                m |= 1ULL << (f->n_src_regs + f->max_dep_loads);
                g_dst_imm_feeds.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_dst_imm_absent.fetch_add(1, std::memory_order_relaxed);
            }
        }
        /*
         * THE DESTINATION FAMILY'S J3 CONTROL (#249), and it is placed on
         * the last line that writes a published mask because nothing
         * earlier can serve.
         *
         * The `mnem` arm every other family's zero is scored against blanks
         * the opcode taxonomy, and the refiner then emits no dep block at
         * all: on aarch64, riscv64 and mipsel the control arm's whole
         * subject vanished, so no dst zero on those ISAs was ever quotable.
         * Two mutations further upstream were built and MEASURED before
         * this one, and both are inert on at least one ISA for a reason
         * worth keeping: scribbling the refiner's mask (`refmask`) moves
         * only the rows this function REFUSED, and corrupting QEMU's write
         * provenance (`wprov`, plugins/api.c) moves only the rows where
         * QEMU's answer and the refiner's DIFFER -- and on aarch64 they
         * agree, because a load's destination is `LOAD0` to both.  A
         * control has to move where the two sources agree as well as where
         * they do not, which is only possible after the choice between
         * them has been made.  So the arm lands here, on the value that
         * actually reaches the wire, and every QDEP_OK destination on every
         * ISA is its subject.
         *
         * It is a control and not a test: it says the chain from this
         * assignment to the scorer's key is live for this family on this
         * ISA.  What the mask is SOURCED from is what the Capstone arms and
         * the two upstream arms measure.
         */
        f->dst_dep_mask[d] = qdep_mutate_is("dstmask") ?
                             qdep_move_mask(f, m) : m;
    }
    g_wstate[QDEP_OK].fetch_add(1, std::memory_order_relaxed);
    if (f->n_dst_regs == 0) {
        /* Nothing was stated about anything; the pass is vacuous. */
        return false;
    }
    g_fact_stated.fetch_add(1, std::memory_order_relaxed);
    return true;
}

const char *state_name(unsigned s)
{
    switch (s) {
    case QDEP_NONE:             return "no accesses / no dataflow ABI";
    case QDEP_OK:               return "PUBLISHED from QEMU's emitters";
    case QDEP_R_STATUS:         return "refused: extraction reported itself incomplete";
    case QDEP_R_SHORT:          return "LOWER BOUND: extraction incomplete, QEMU's read list taken anyway";
    case QDEP_R_NORECORD:       return "refused: qemu withheld the access list or a provenance";
    case QDEP_R_FIELD:          return "refused: provenance named env state with no generic word";
    case QDEP_R_UNMAPPED:       return "refused: provenance named a global with no generic word";
    case QDEP_R_WIDE:           return "refused: more address registers than the record holds";
    case QDEP_R_UNREPRESENTABLE:return "refused: a named input occupies no slot to set";
    case QDEP_R_EMU_MONITOR:    return "refused: names the reservation monitor's value half (emulation artefact, #177 / f46873a738)";
    case QDEP_R_REINDEX:        return "refused: QEMU's own source index does not fit (src slots or mask width)";
    case QDEP_R_HELPER_UNSTATED:return "refused: a helper-performed access whose operand travels through no argument (CP1)";
    case QDEP_NO_BLOCK:         return "stated by QEMU but the wire's HAS_REG flag is clear: consumer already at the default";
    case QDEP_R_DST_UNNAMED:    return "refused: a wire destination QEMU named only as env state, not as a TCG global (#218)";
    case QDEP_R_DST_UNSTATED_CONST: return "refused: a destination's value came from a constant that is neither the encoding nor the zero register";
    case QDEP_R_DST_IMM_UNSTATED: return "refused: the instruction carries an immediate QEMU's provenance cannot mention, so a register-only mask would be short by the immediate bit";
    case QDEP_R_DST_IMM_UNSTATED_PATH: return "refused: the instruction carries an immediate NO DECODER ON ITS PATH STATES, so an absent immediate-provenance bit means nobody looked (#248 coverage)";
    case QDEP_R_DST_IMM_FOLDED: return "refused: the decoder stated this instruction's immediate and QEMU folded the value away before any op read it, so the absent bit is the emulator's optimisation";
    default:                    return "?";
    }
}

/*
 * WHETHER THE DEPENDENCY BLOCK EXISTS.  QEMU DECIDES (R12).
 *
 *   "WE ARE REMOVING CAPSTONE.  WHY ARE WE LETTING CAPSTONE DECIDE THIS?"
 *
 * The rule is one line: a block exists when QEMU stated a dependency fact
 * for this instruction.  @qemu_dst is that fact for the destination family
 * -- dst_precheck() proved every wire destination has a QEMU write row and
 * apply_dst() wrote every slot's mask from it -- and @qemu_sdata is that
 * fact for the store-data family, QEMU's provenance for every store slot.
 * Neither reads a Capstone mask; the refiner's answer is not an input to
 * this decision and there is no "either side" arm.
 *
 * WHAT SURVIVES, AND WHY IT IS NOT AN EITHER-SIDE ARM (R12.1).
 *
 *   "Removing capstone does not mean an acceptance of degradation in our
 *    trace.  We should lose NO information.  This whole ARC is about using
 *    QEMU to derive the information we were getting from Capstone.  Do not
 *    use this ruling as a justification for dropping information out of the
 *    trace, because I know you will try to."
 *
 * A row QEMU cannot yet state is a row whose content nothing has adjudicated
 * wrong.  Dropping its block would widen a real, published dependency set to
 * the all-to-all default and call the widening a removal, which is exactly
 * the move that ruling forbids.  So it publishes as it always did, and the
 * difference from an either-side rule is that this population is BOUNDED,
 * ENUMERATED and NAMED: @why is the reason QEMU could not state the row,
 * which is also the coverage path that retires it, and every survivor lands
 * in g_survivor_sig under its mnemonic and that reason.  The list shrinks as
 * the emitters learn to state those facts; when it is empty this route and
 * InsnFields::refiner_dep_stated are deleted.  It is an interim state with a
 * direction, not an endpoint.
 *
 * ONE THING IT MAY NEVER DO is suppress a block QEMU's facts call for -- the
 * survivor test is consulted only where @qemu_dst and @qemu_sdata are both
 * false.  g_blk_qemu_unpublished is the must-be-0 that says so.
 *
 * AND THE **ADDRESS** BLOCK IS DECIDED HERE TOO, on the same rule (#264).
 * @qemu_addr_facts is how many of this instruction's accesses QEMU stated an
 * address for; one is enough, because one stated fact is a fact and the
 * slots beside it publish the format's own default written out.  It lives
 * here rather than in qdep_apply()'s address section for the reason R12
 * exists: a block's EXISTENCE is one decision on one rule, and while the two
 * bits were decided in two places one of them could -- and did -- delete an
 * address QEMU had stated in full.  Grep for `has_addr_deps =` and this is
 * the only line in the QEMU regime that writes it true.
 */
void decide_block(InsnFields *f, bool qemu_dst, bool qemu_sdata,
                  unsigned qemu_addr_facts,
                  const char *mnem, unsigned wstate, const char *why)
{
    f->has_addr_deps = qemu_addr_facts != 0;
    g_addr_fact_carried.fetch_add(f->has_addr_deps ? qemu_addr_facts : 0u,
                                  std::memory_order_relaxed);
    if (qemu_dst || qemu_sdata) {
        f->has_reg_deps = true;
        g_fact_carried.fetch_add((qemu_dst ? 1u : 0u) + (qemu_sdata ? 1u : 0u),
                                 std::memory_order_relaxed);
        if (!qemu_dst && f->n_dst_regs) {
            /*
             * The store datum is QEMU's and the destinations are not, so
             * this block's two halves have two sources.
             *
             * AND THE DESTINATION HALF MUST STILL SAY SOMETHING TRUE.  A
             * block that exists publishes every destination slot, and the
             * bytes sitting in dst_dep_mask[] are not automatically an
             * answer: where no refiner ever wrote them they are the array's
             * zero initialisation, and publishing zero says "this
             * destination depends on nothing", which is a CLAIM and a false
             * one.  Measured on the three `rep stosq` PCs, whose block the
             * store leg restores: RDI and RCX would have gone out as EMPTY.
             * The block existing is a gain; a fabricated narrow mask riding
             * in with it is not, and R12.1 no more permits inventing content
             * than dropping it.
             *
             * So the two cases are separated.  A refiner that STATED the
             * destinations keeps them -- that is the survivor clause, the
             * content is what it always was, and nothing is lost.  A row
             * with no stated destination answer publishes the format's own
             * all-inputs default WRITTEN OUT, exactly as the store-data half
             * does in the mirror-image case: the consumer reads precisely
             * what it read when there was no block, so the destination half
             * carries no new information and no false information either.
             */
            if (!f->refiner_dep_stated) {
                for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                    f->dst_dep_mask[d] = all_inputs_mask(f);
                }
                g_blk_mixed_default.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_blk_mixed.fetch_add(1, std::memory_order_relaxed);
                note_survivor(mnem, wstate, why);
            }
        } else {
            g_blk_qemu.fetch_add(1, std::memory_order_relaxed);
        }
        return;
    }
    if (f->refiner_dep_stated) {
        f->has_reg_deps = true;
        g_blk_survivor.fetch_add(1, std::memory_order_relaxed);
        note_survivor(mnem, wstate, why);
        return;
    }
    f->has_reg_deps = false;
    g_blk_absent.fetch_add(1, std::memory_order_relaxed);
}

}  /* namespace */

/*
 * THE PER-ENCODING CORPORA.  See the declarations in
 * champsim_tracer_qdep.h for why a host tool cannot derive these and has to
 * be handed them.
 *
 * TWO SUBJECTS, ONE MECHANISM.  The read-list corpus exports the source
 * registers the wire publishes for an encoding; the opcode-class corpus
 * exports the GenericOpcode it publishes for the same encoding.  Everything
 * around those two columns is identical -- the env gate, the open-once, the
 * dedup key, the hex spelling, the per-row flush -- so it is written once
 * here and instantiated twice.  A second hand-copied dumper is how the
 * truncation defect described below gets fixed in one corpus and not the
 * other.
 *
 * DEDUPLICATED ON THE ENCODING, which is why the state is a member and not
 * the caller's: a hot loop executes one encoding millions of times and a
 * corpus wants it once.  The key is the exact byte string AND its length,
 * so two encodings that differ in a field nothing reads are still two rows
 * -- the sweeps these feed enumerate encodings, and folding distinct ones
 * together here would silently narrow them.
 *
 * A ROW IS WRITTEN ONCE AND NEVER REVISED.  What an encoding publishes is a
 * function of the encoding and the tables, so a second sighting has nothing
 * to add; where that stops being true the corpus builder's own duplicate
 * check reports a CONFLICT rather than letting the last writer win.
 */
namespace {

struct EncCorpus {
    const char *env;                 /* the variable that asks for it */
    const char *header;              /* the TSV header line it writes */
    std::atomic<int> state{0};       /* 0 unasked, 1 open, 2 failed */
    FILE *fp = nullptr;
    std::mutex lock;
    std::set<std::array<uint8_t, MAX_INSN_BYTES + 1> > seen;
    std::atomic<uint64_t> rows{0};

    /*
     * Is this corpus taking rows?  Resolves the env variable exactly once
     * and latches the answer; with the variable unset every later call is a
     * single relaxed load.
     */
    bool live()
    {
        int st = state.load(std::memory_order_relaxed);

        if (st == 2) {
            return false;
        }
        if (st == 0) {
            std::lock_guard<std::mutex> lk(lock);
            if (state.load(std::memory_order_relaxed) == 0) {
                const char *path = getenv(env);

                if (!path) {
                    state.store(2, std::memory_order_relaxed);
                    return false;
                }
                fp = fopen(path, "w");
                if (!fp) {
                    state.store(2, std::memory_order_relaxed);
                    return false;
                }
                fputs(header, fp);
                state.store(1, std::memory_order_relaxed);
            }
        }
        return state.load(std::memory_order_relaxed) == 1;
    }

    /* First sighting of this encoding?  Caller holds nothing; this takes
     * the lock and keeps it for the write, so a row cannot be claimed by
     * one thread and written by another. */
    bool claim(std::unique_lock<std::mutex> &lk,
               const uint8_t *bytes, uint8_t n)
    {
        std::array<uint8_t, MAX_INSN_BYTES + 1> key{};

        key[0] = n;
        for (uint8_t i = 0; i < n; i++) {
            key[i + 1] = bytes[i];
        }
        lk = std::unique_lock<std::mutex>(lock);
        return seen.insert(key).second;
    }

    void write(const char *row)
    {
        fputs(row, fp);
        /*
         * FLUSHED PER ROW, and this is not caution -- it is a defect this
         * path had and the corpus builder caught on its first run.  Nothing
         * closes this stream: the plugin's exit path does not own it, so the
         * FINAL row sat in stdio's buffer and reached the file cut in half.
         * The mipsel capture's last line read `mipsel<TAB>41006014<TAB>bn` --
         * a mnemonic sheared mid-word, no source column, no newline.
         *
         * A corpus that silently loses its tail is worse than one that
         * refuses: the truncated row still PARSES, as a row whose payload
         * column is empty, so a gate reading it would score that encoding as
         * publishing nothing and report no error at all.  Both of the two
         * "conflicting encodings" the builder reported on that run were
         * this, and both went away here.
         *
         * The cost is bounded by the DEDUPLICATION above -- one flush per
         * distinct encoding, never per executed instruction -- and the whole
         * path is off unless asked for.
         */
        fflush(fp);
        rows.fetch_add(1, std::memory_order_relaxed);
    }
};

EncCorpus g_src_enc{"CST_SRC_ENC_DUMP", "#isa\tencoding\tmnem\tsrc\n"};
EncCorpus g_opc_enc{"CST_OPC_ENC_DUMP", "#isa\tencoding\tmnem\topcode\n"};
EncCorpus g_src_mech{"CST_SRC_MECH_DUMP",
    "#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate"
    "\tPUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\n"};

/* The encoding, hex, as both corpora spell it.  @out must hold
 * 2 * MAX_INSN_BYTES + 1 bytes; returns the clamped length in BYTES. */
uint8_t enc_hex(char *out, const uint8_t *bytes, uint8_t size)
{
    uint8_t n = size < MAX_INSN_BYTES ? size : (uint8_t)MAX_INSN_BYTES;

    for (uint8_t i = 0; i < n; i++) {
        static const char d[] = "0123456789abcdef";
        out[2 * i]     = d[bytes[i] >> 4];
        out[2 * i + 1] = d[bytes[i] & 0xf];
    }
    out[2 * n] = '\0';
    return n;
}

}  /* namespace */

bool src_mech_corpus_live(void)
{
    return g_src_mech.live();
}

void dump_src_enc_row(const InsnFields *f, const uint8_t *bytes,
                      uint8_t size, const char *mnem)
{
    if (!f || !bytes || !size || !g_src_enc.live()) {
        return;
    }

    char hex[2 * MAX_INSN_BYTES + 1];
    uint8_t n = enc_hex(hex, bytes, size);
    std::unique_lock<std::mutex> lk;

    if (!g_src_enc.claim(lk, bytes, n)) {
        return;
    }

    GString *g = g_string_new(nullptr);

    g_string_append_printf(g, "%s\t%s\t%s\t",
                           target_name ? target_name : "?",
                           hex, mnem ? mnem : "?");
    reglist_str(g, f->src_regs, f->n_src_regs);
    g_string_append_c(g, '\n');
    g_src_enc.write(g->str);
    g_string_free(g, TRUE);
}

void dump_opc_enc_row(const InsnFields *f, const uint8_t *bytes,
                      uint8_t size, const char *mnem)
{
    if (!f || !bytes || !size || !g_opc_enc.live()) {
        return;
    }

    char hex[2 * MAX_INSN_BYTES + 1];
    uint8_t n = enc_hex(hex, bytes, size);
    std::unique_lock<std::mutex> lk;

    if (!g_opc_enc.claim(lk, bytes, n)) {
        return;
    }

    GString *g = g_string_new(nullptr);

    /*
     * BY NAME, not by number.  The GenericOpcode enumerators are dense and
     * renumber whenever one is inserted, so a corpus of integers taken
     * before a table edit and one taken after would compare as a wholesale
     * class move with nothing having happened.  The names are the stable
     * subject, and they are what an adjudication ledger has to be written
     * in to stay readable.
     */
    g_string_append_printf(g, "%s\t%s\t%s\t%s\n",
                           target_name ? target_name : "?",
                           hex, mnem ? mnem : "?",
                           generic_opcode_name_or_unknown(f->opcode));
    g_opc_enc.write(g->str);
    g_string_free(g, TRUE);
}

/*
 * THE PER-ENCODING MECHANISM CORPUS.  See champsim_tracer_qdep.h.
 *
 * Every column is the answer qdep_apply() staged for THIS instruction;
 * nothing is recomputed here, because a second computation from a different
 * vantage point is a second opinion and this file already has the first one.
 *
 * A stage that does not name @pc is DROPPED and counted.  That happens when
 * qdep_apply() did not run for the encoding being written -- a decode with
 * no dependency block at all -- and printing the PREVIOUS instruction's
 * mechanism under this encoding would be a fabricated row, which is the one
 * failure mode a corpus like this must not have.  A dropped row leaves the
 * encoding UNREACHED downstream, which is the honest reading.
 */
void dump_src_mech_row(uint64_t pc, const InsnFields *f, const uint8_t *bytes,
                       uint8_t size, const char *mnem)
{
    if (!f || !bytes || !size || !g_src_mech.live()) {
        return;
    }

    SrcMechStage *m = &g_mech_stage;

    if (!m->valid || m->pc != pc) {
        g_mech_stage_mismatch.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    /* Consumed exactly once: the next encoding gets its own stage or none. */
    m->valid = false;

    char hex[2 * MAX_INSN_BYTES + 1];
    uint8_t n = enc_hex(hex, bytes, size);
    std::unique_lock<std::mutex> lk;

    if (!g_src_mech.claim(lk, bytes, n)) {
        return;
    }

    GString *g = g_string_new(nullptr);

    g_string_append_printf(g, "%s\t%s\t%s\t%08x\t%s\t%s\t%s\t",
                           target_name ? target_name : "?",
                           hex, mnem ? mnem : "?",
                           m->decode_id, m->rule ? m->rule : "?",
                           state_name(m->src_state),
                           state_name(m->wstate));
    reglist_str(g, f->src_regs, f->n_src_regs);
    g_string_append_c(g, '\t');
    reglist_str(g, m->qn, m->n_qn);
    g_string_append_c(g, '\t');
    reglist_str(g, m->sv, m->n_sv);
    g_string_append_c(g, '\t');
    reglist_str(g, m->rd, m->n_rd);
    g_string_append_c(g, '\t');
    g_string_append_printf(g, "%s%s%s%s%s%s",
                           m->status_flags & 0x01 ? "memops_truncated," : "",
                           m->status_flags & 0x02 ? "memops_unnoted," : "",
                           m->status_flags & 0x04 ? "fields_truncated," : "",
                           m->status_flags & 0x08 ? "writes_truncated," : "",
                           m->status_flags & 0x10 ? "prov_truncated," : "",
                           m->status_flags & 0x20 ? "helper_unbounded," : "");
    if (!m->status_flags) {
        g_string_append(g, "-");
    }
    g_string_append_c(g, '\t');
    g_string_append_printf(g, "%s:", state_name(m->srcx_state));
    reglist_str(g, m->rdx, m->n_rdx);
    g_string_append_c(g, '\t');
    for (uint8_t k = 0; k < m->n_cont; k++) {
        /* TWO calls, TWO statements: generic_reg_name_or_unknown() answers a
         * bank register out of one thread-local buffer, so two calls in one
         * argument list alias and both %s print the same bound.  The per-pc
         * witness printed `REG_FPR0..REG_FPR0` for the whole x87 file that
         * way; this site does not repeat it. */
        g_string_append_printf(g, "%s%s", k ? "," : "",
                               generic_reg_name_or_unknown(m->cont_lo[k]));
        g_string_append_printf(g, "..%s",
                               generic_reg_name_or_unknown(m->cont_hi[k]));
    }
    if (!m->n_cont) {
        g_string_append(g, "-");
    }
    /*
     * XLAT -- THE TRANSLATION'S SHAPE, and WR -- QEMU's write side.
     *
     * The columns that let a reader ask whether the row describes an
     * INSTRUCTION at all.  Everything to the left of them is what QEMU said
     * about the operands of a translation; these two say what the
     * translation WAS.  An enable check that refused reads `noret=1` with
     * no accesses and no architectural destination, and every other column
     * on the row still reads exactly like an instruction QEMU stated few
     * reads for -- which is how 38,400 aarch64 access traps were scored as
     * losses before this column existed.
     *
     * `shape=-` where the status read itself failed: the counts are then
     * not zero, they are absent, and a reader must not take an absent count
     * for a measured one.
     */
    g_string_append_c(g, '\t');
    if (m->x_have_shape) {
        g_string_append_printf(g, "noret=%u,calls=%u,memr=%u,memw=%u",
                               m->x_noreturn_calls, m->x_calls,
                               m->x_mem_reads, m->x_mem_writes);
    } else {
        g_string_append(g, "shape=-");
    }
    g_string_append_c(g, '\t');
    reglist_str(g, m->wr, m->n_wr);
    g_string_append_c(g, '\n');
    g_src_mech.write(g->str);
    g_string_free(g, TRUE);
}


void qdep_note_insn(const struct qemu_plugin_tb *tb, size_t idx, QDepInsn *out)
{
    qemu_plugin_dataflow_memop mo[kMaxMemops];
    qemu_plugin_dataflow_status st;
    unsigned n;

    memset(out, 0, sizeof(*out));
    out->state = QDEP_NONE;
    out->data_state = QDEP_NONE;

    qdep_init();
    if (!g_live) {
        return;
    }
    /*
     * Read before anything can refuse: the identity is what a refusal has to
     * be reported AGAINST, so taking it only on the success path would make
     * the refusing rows the ones with no name.
     */
    {
        struct qemu_plugin_insn *ins = qemu_plugin_tb_get_insn(tb, idx);

        if (ins) {
            out->decode_id = qemu_plugin_insn_decode_id(ins);
            out->decode_name = qemu_plugin_insn_decode_name(ins);
            out->insn_vaddr = qemu_plugin_insn_vaddr(ins);
        }
    }

    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        out->state = out->data_state = out->dst_state =
            out->src_state = QDEP_R_NORECORD;
        return;
    }
    /*
     * THE TRANSLATION'S SHAPE, taken here -- BEFORE any refusal return.
     *
     * A sweep's question "did QEMU translate this instruction's body, or
     * only the trap an enable check raised for it?" is asked most often
     * about the instructions whose extraction refused, so a reader that
     * only got the shape on the clean path would be blind exactly where it
     * is needed.  Nothing on the wire path reads these; see QDepInsn.
     */
    out->x_have_shape     = 1;
    out->x_calls          = (uint8_t)(st.n_calls > 255 ? 255 : st.n_calls);
    out->x_noreturn_calls = (uint8_t)(st.n_noreturn_calls > 255
                                      ? 255 : st.n_noreturn_calls);
    out->x_mem_reads      = (uint8_t)(st.n_mem_reads > 255
                                      ? 255 : st.n_mem_reads);
    out->x_mem_writes     = (uint8_t)(st.n_mem_writes > 255
                                      ? 255 : st.n_mem_writes);

    /*
     * memops_unnoted is the one that matters most here and it is checked
     * FIRST: it says an access happened that no emitter note accounted for,
     * so the list below is not merely capped, it is missing a member whose
     * address nothing states.  fields/writes/prov truncation are included
     * because a provenance that lost a source to slot exhaustion produces
     * precisely a short set.
     *
     * Since the wire's SLOT COUNT is this list's length, every flag here is
     * also a statement that the count is a lower bound rather than the MAX
     * the template header means -- which is why `have_list` stays false on
     * this path and the counts reach the format default instead.
     *
     * n_helper_unbounded is the fourth, and it is the one an earlier draft
     * of this file did not check.  Its own contract says the reported sets
     * "are then SHORT, not merely coarse" -- a helper handed the whole CPU
     * state, whose real reads no op names.  A store lowered through such a
     * helper would arrive here with an EMPTY data provenance that means "the
     * walk could not see" and not "nothing was read", and publishing it
     * would be the short mask this file exists to never publish.
     *
     * n_helper_unknown is NOT in this list, and the difference is the point.
     * Unknown DIRECTION is recorded as read-and-written, which is the
     * over-approximation; unbounded FOOTPRINT is a set with members missing.
     * Refusing on the first would be irdf's `n_calls > 0` decline, which R5
     * ruled is a reader's limit written down as the machine's.
     */
    out->status_flags =
        (uint8_t)((st.memops_truncated  ? 0x01 : 0) |
                  (st.memops_unnoted    ? 0x02 : 0) |
                  (st.fields_truncated  ? 0x04 : 0) |
                  (st.writes_truncated  ? 0x08 : 0) |
                  (st.prov_truncated    ? 0x10 : 0) |
                  (st.n_helper_unbounded? 0x20 : 0));
    if (out->status_flags) {
        /*
         * REFUSED, exactly as before -- and MEASURED on the way out.
         *
         * The read list is taken here and parked in @srcx, which nothing on
         * the wire path reads.  It answers the one question the refusal
         * makes unanswerable from outside: on an instruction whose
         * extraction reports itself short, did QEMU state any reads at all?
         * "Refused" and "there is nothing to refuse" print identically in
         * the census and want opposite remedies -- a note at the emitter
         * versus a survivor row -- and 30 of the 33 program counters the
         * operand walk's read arm was the only supplier for land here.
         */
        note_src(tb, idx, out);
        out->srcx_state = out->src_state;
        out->n_srcx = out->n_src;
        memcpy(out->srcx, out->src_reg, sizeof(out->srcx));
        out->state = out->data_state = out->dst_state = QDEP_R_STATUS;
        /*
         * The MEMORY and DESTINATION families are refused exactly as before:
         * their subject is a LIST WHOSE LENGTH the wire publishes, and a
         * short list there is a short mask.  The READ list is not that: it
         * is a set, the wire's src_regs[] is a union, and a member missing
         * from it costs a source the operand walk still supplies today.  So
         * the read list survives the gate as a LOWER BOUND -- see
         * QDEP_R_SHORT -- and it is empty-with-a-reason where note_src()
         * itself refused.
         */
        out->src_state = (out->src_state == QDEP_OK && out->n_src)
                       ? QDEP_R_SHORT : QDEP_R_STATUS;
        if (out->src_state != QDEP_R_SHORT) {
            out->n_src = 0;
            memset(out->src_reg, 0, sizeof(out->src_reg));
        }
        return;
    }

    /*
     * The two encoded-immediate facts, carried whole to the destination
     * family (#248).  Not a refusal condition on their own: an instruction
     * whose decoder never states an immediate is perfectly extractable in
     * every other respect, and only the one rule that would read an ABSENT
     * immediate bit as an answer has to know.
     */
    out->imm_stated = st.imm_stated;
    out->imm_reached = st.imm_reached;
    out->imm_non_dataflow = st.imm_non_dataflow;
    /*
     * The destination-side unbounded flag, carried but NOT acted on -- see
     * QDepInsn::writes_unbounded.  It is deliberately not in the refusal
     * test above: st.n_helper_unbounded there is about SOURCES the walk
     * could not see, and refusing on it keeps a short mask off the wire.
     * This one is about a DESTINATION QEMU wrote and could not name, which
     * only matters once the wire's list is QEMU's -- i.e. at the flip.
     */
    out->writes_unbounded = st.helper_writes_unbounded;

    /*
     * The source list, taken HERE rather than beside note_dst(), because it
     * does not depend on the access list and an instruction with no memop
     * returns through a different path below.  Extracting it once, before
     * that fork, is what keeps the census's population equal to the
     * population the status gate admitted.
     */
    note_src(tb, idx, out);

    for (unsigned i = 0; i < kMaxMemops; i++) {
        mo[i].struct_size = sizeof(mo[i]);
    }
    n = qemu_plugin_insn_memops(tb, idx, mo, kMaxMemops);
    if (n == QEMU_PLUGIN_DF_INCOMPLETE || n > kMaxMemops) {
        out->state = out->data_state = out->dst_state =
            out->src_state = QDEP_R_NORECORD;
        return;
    }

    /*
     * From here the ACCESS LIST IS WHOLE, and that is the fact the slot
     * counts are taken from.  It stays true even when a provenance below is
     * refused: how many accesses there are and what each depends on are two
     * different questions, and only the second can fail on its own.
     */
    out->have_list = true;

    if (n == 0) {
        /*
         * No accesses: nothing to state for either MEMORY family.  The
         * destination family does not read the access list and is extracted
         * all the same -- an ALU instruction has no memop and is exactly
         * where dst_dep[] carries the whole of the answer.
         */
        uint8_t no_loads[kMaxMemops];

        memset(no_loads, 0xFF, sizeof(no_loads));
        out->state = out->data_state = QDEP_NONE;
        note_dst(tb, idx, out, no_loads, 0);
        return;
    }

    /*
     * Ordinals within each direction.  QEMU numbers the accesses in one
     * list; the wire numbers loads and stores separately, and the load-data
     * provenance bits are numbered the FIRST way while the mask band they
     * feed is indexed the SECOND.  @load_ord translates, and it exists
     * because on `lock cmpxchgl` the two happen to agree and on anything
     * whose accesses interleave they do not.
     */
    uint8_t load_ord[kMaxMemops];
    memset(load_ord, 0xFF, sizeof(load_ord));

    /*
     * The two families are extracted in one pass but refused INDEPENDENTLY.
     * They are separate parameters of the same emitter and separate blocks on
     * the wire, and folding one's refusal into the other would throw away an
     * answer QEMU gave -- which is the same shape of loss as publishing a
     * short mask, one level up.
     */
    std::vector<uint64_t> w(g_prov_words);
    for (unsigned i = 0; i < n; i++) {
        bool store = mo[i].is_store != 0;
        QDepState rc;
        uint8_t a;

        /*
         * More accesses of one direction than this extractor holds.  QEMU's
         * own cap IS this number -- QDEP_MAX_ACCESS is defined as
         * INSN_DF_MAX_MEMOPS rather than as a literal, so the two cannot
         * drift apart -- and reaching it here therefore means the list is
         * whole and simply wider than the arrays: refuse the COUNT for that
         * direction rather than publish a truncated slot layout.
         */
        if ((store ? out->n_stores : out->n_loads) >= QDEP_MAX_ACCESS) {
            out->state = out->data_state = out->dst_state =
            out->src_state = QDEP_R_STATUS;
            out->have_list = false;
            return;
        }
        if (store) {
            a = out->n_stores++;
        } else {
            a = out->n_loads++;
            load_ord[i] = a;
        }
        /*
         * mo[i].count_unbounded is DELIBERATELY not consulted.  It says a
         * helper repeats THIS ONE stated access a data-dependent number of
         * times, and the slot count has never been a bound on the dynamic
         * count -- see champsim_tracer_qdep.h, and mnemonics.h on XSAVEOPT.
         * One record is one slot carrying one address mask either way.
         */
        if (qemu_plugin_insn_memop_addr_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            out->state = out->data_state = out->dst_state =
            out->src_state = QDEP_R_NORECORD;
            out->have_list = false;
            return;
        }
        /*
         * CP1.  A helper-performed access whose address is not one of the
         * helper's arguments hands over an EMPTY provenance, and folding it
         * would publish "this address depends on nothing" for an access that
         * genuinely reads registers -- the short mask this file exists never
         * to write.  The COUNT is still exact, because the access was
         * stated; only the mask is refused.
         */
        if (mo[i].addr_unstated) {
            if (out->state == QDEP_NONE) {
                out->state = QDEP_R_HELPER_UNSTATED;
            }
            rc = QDEP_R_HELPER_UNSTATED;
        } else {
            rc = store
                ? fold_prov(w.data(), out->store_addr_regs[a],
                            &out->n_store_addr_regs[a], nullptr, nullptr)
                : fold_prov(w.data(), out->load_addr_regs[a],
                            &out->n_load_addr_regs[a], nullptr, nullptr);
        }
        /*
         * The verdict lands on THIS access.  @state still takes the first
         * refusal, because the census reports one reason per instruction and
         * the first one is the one that names the coverage path -- but it no
         * longer decides the other slots.  A helper-performed access whose
         * address travels through no argument is recorded as unstated here
         * rather than only in @state: fold_prov() would have returned OK on
         * its empty provenance, and an empty set means "not stated", never
         * "depends on nothing".
         */
        if (store) {
            out->store_addr_state[a] = (uint8_t)rc;
        } else {
            out->load_addr_state[a] = (uint8_t)rc;
        }
        if (rc != QDEP_OK && out->state == QDEP_NONE) {
            out->state = rc;    /* first refusal wins; a later access
                                 * succeeding does not undo it */
        }

        if (!store) {
            continue;
        }
        if (mo[i].data_unstated) {
            if (out->data_state == QDEP_NONE) {
                out->data_state = QDEP_R_HELPER_UNSTATED;
            }
            continue;
        }
        if (qemu_plugin_insn_memop_data_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            if (out->data_state == QDEP_NONE) {
                out->data_state = QDEP_R_NORECORD;
            }
            continue;
        }
        uint8_t memop_slots = 0;
        rc = fold_prov(w.data(), out->store_data_regs[a],
                       &out->n_store_data_regs[a], &memop_slots, nullptr);
        if (rc == QDEP_OK) {
            /*
             * Translate MEMOP ordinals into LOAD ordinals.  A bit naming an
             * access that is not one of this instruction's loads is one this
             * extractor cannot place in the load-data band, and placing it
             * anywhere else would name a slot that means something different
             * -- so it is refused rather than approximated.
             */
            for (unsigned k = 0; k < QDEP_MAX_ACCESS; k++) {
                if (!(memop_slots & (1u << k))) {
                    continue;
                }
                if (k >= n || load_ord[k] == 0xFF) {
                    rc = QDEP_R_UNREPRESENTABLE;
                    break;
                }
                out->store_data_load_slots[a] |=
                    (uint8_t)(1u << load_ord[k]);
            }
        }
        if (rc != QDEP_OK && out->data_state == QDEP_NONE) {
            out->data_state = rc;   /* first refusal wins */
        }
    }
    /*
     * A family with no refusal recorded above was stated in full.  Written
     * this way round rather than as an early `= QDEP_OK` so that the FIRST
     * refusal wins and a later access cannot overwrite it with a success.
     */
    if (out->state == QDEP_NONE) {
        out->state = QDEP_OK;
    }
    if (out->data_state == QDEP_NONE && out->n_stores > 0) {
        out->data_state = QDEP_OK;
    }
    note_dst(tb, idx, out, load_ord, n);
}

/*
 * THE J3 CONTROL CANDIDATE THAT SCORES THE REFINER, not QEMU (#249).
 *
 * Every mask the destination family publishes is written twice: the row's
 * `.dep_refine` writes one from Capstone's operand detail, and qdep_apply()
 * below overwrites it with QEMU's provenance -- or does NOT, on the rows it
 * refuses, where the refiner's answer is what reaches the wire.  Scribbling
 * the refiner's mask HERE, in the window between the two writers, therefore
 * moves exactly the destination slots the wire still takes from Capstone,
 * and nothing else.  It is a measurement of the family's residual coupling
 * with the sign of a control: rows that move are rows QEMU did not decide.
 *
 * NON-EMPTINESS IS PRESERVED, because emptiness is a decision elsewhere:
 * dep_publish() reads the refiner's mask to decide whether a dep block
 * exists at all (#242/#247), so a scribble that emptied a mask, or filled
 * an empty one, would change which blocks are on the wire and the movement
 * would be the block gate's rather than the mask's.  Flipping the immediate
 * bit of a non-empty mask cannot do either.
 */
void qdep_mutate_refiner_dst(InsnFields *f)
{
    if (!qdep_mutate_is("refmask") || !f || !f->dst_dep_mask) {
        return;
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] = qdep_move_mask(f, f->dst_dep_mask[d]);
    }
}

void qdep_apply(InsnFields *f, InsnRegNames *rn, const QDepInsn *q,
                const char *mnem)
{
    if (!g_live || !q) {
        /*
         * The dataflow ABI handshake never succeeded, so there is no answer
         * to prefer and nothing to displace.  The counts stay exactly as the
         * operand walk left them: zeroing them here would gut every memory
         * annotation in the trace to say something this file did not learn.
         * The disablement itself is reported by name in qdep_report().
         *
         * has_reg_deps keeps the provisional value dep_publish() left in it.
         * This is the one regime where the refiner's answer reaches the wire
         * as a DECISION, and it is not R12's rule bending: R12 gives the
         * block to QEMU's facts, and here QEMU stated no facts at all -- for
         * any instruction, for the whole run.  Dropping every block instead
         * would be the degradation R12.1 forbids, taken for no gain.
         */
        g_state[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        g_dstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        g_wstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    unsigned state = q->state;
    unsigned dstate = q->data_state;
    char wwhy[64] = "";

    /* ---------------- ADMISSION: the slot counts are QEMU's ------------- */
    /*
     * How many load slots and store slots this instruction HAS is now the
     * length of QEMU's access list for each direction, and no longer the
     * number of memory OPERANDS the Capstone walk enumerated.  The two were
     * never answers to the same question -- one operand is two accesses on
     * `vmovdqu`, `ldp` and `stp`, and `lock cmpxchgl` has a store no operand
     * counted -- and the count is what sizes the mask arrays, fixes the
     * register masks' load-data and immediate bit offsets, and decides
     * whether a runtime memop finds a static slot at all.
     *
     * When QEMU cannot state a direction's count the direction reaches the
     * format's own default, ZERO slots: no mask array, the consumer back at
     * all-to-all, and the DYNAMIC count still riding CST_FID_N_LOADS /
     * CST_FID_N_STORES.  It never falls back to the operand walk's number.
     */
    const uint8_t mdl_old = f->max_dep_loads;
    const uint8_t mds_old = f->max_dep_stores;
    uint8_t mdl_new = 0, mds_new = 0;
    unsigned adm = QDEP_OK;

    if (!q->have_list) {
        adm = (state == QDEP_R_STATUS) ? QDEP_R_STATUS : QDEP_R_NORECORD;
    } else {
        mdl_new = q->n_loads;
        mds_new = q->n_stores;
    }

    f->max_dep_loads  = mdl_new;
    f->max_dep_stores = mds_new;

    /*
     * The register masks were written against the OLD load run and have to
     * be re-seated onto the new one.  store_data_dep_mask[] is overwritten
     * in full further down and needs no carry; dst_dep_mask[] is overwritten
     * only where QEMU could state it, so the carry is what keeps the rows it
     * could NOT state readable in the new layout -- those keep the refiner's
     * answer, and a refiner's answer indexed against a load run that no
     * longer exists would name a slot that means something else.
     */
    if (mdl_old != mdl_new) {
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            bool lost = false;
            uint64_t v = carry_load_band(f->dst_dep_mask[d], f->n_src_regs,
                                         mdl_old, mdl_new, &lost);
            f->dst_dep_mask[d] = lost ? all_inputs_mask(f) : v;
        }
    }

    /*
     * Seat QEMU's own register list at the head of src_regs[], so every mask
     * written below is written in a coordinate system QEMU owns.  Done after
     * the counts and before the masks, because the permutation carries the
     * load-data band with it and that band's width is the count just set.
     *
     * AND BEFORE THE NO-SLOT RETURN, which it was not until the destination
     * family arrived.  An instruction with no memory access used to leave
     * here with nothing to write; it now has a dst_dep[] to write, and a
     * mask indexed against the operand walk's order while claiming to be
     * QEMU's is exactly the coupling J3 measured and refused.
     */
    unsigned wstate = dst_precheck(f, q, wwhy, sizeof(wwhy));
    /*
     * THE #236 FLIP'S REFUSE ROUTE, COUNTED (not taken).
     *
     * Counted HERE and not in qdep_note_insn() because the question only
     * exists where the wire has a destination list to replace: an
     * instruction with no destination slot has nothing for the flip to get
     * wrong.  `f->n_dst_regs` is that list, and it does not exist until the
     * template builder has run.
     *
     * This is the population the flip would have to REFUSE rather than
     * publish, because QEMU's write list is short by a register whose index
     * the source does not state.  It is a lower bound on nothing and an
     * upper bound on nothing -- it is exactly the set, and it is counted
     * before the flip so the flip's cost is measured rather than argued.
     */
    if (q->writes_unbounded && f->n_dst_regs) {
        g_dst_would_refuse_unbounded.fetch_add(1, std::memory_order_relaxed);
    }
    {
        uint8_t qregs[MAX_SRC_REGS];
        uint8_t nq = qemu_named_regs(q, qregs, f, wstate == QDEP_OK);

        if (nq && !reindex_src_for_qemu(f, rn, qregs, nq)) {
            /*
             * The index could not be seated, so nothing below can be
             * written in QEMU's coordinates.  Refuse all three families
             * rather than publish a mask indexed against the operand walk's
             * order while claiming it is QEMU's.
             */
            g_state[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            g_dstate[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            note_refusal(mnem, QDEP_R_REINDEX, "dst  ", nullptr);
            g_wstate[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            /*
             * QEMU stated nothing this row can carry, so the block is the
             * survivor route's if the refiner had content.  The store masks
             * are still widened to the default where one publishes: their
             * Capstone value may not reach the wire (fb92a61ea4), and that
             * widening predates this flip rather than arriving with it.
             */
            decide_block(f, false, false, 0, mnem, QDEP_R_REINDEX,
                         nullptr);
            if (f->has_reg_deps) {
                for (uint8_t st = 0; st < f->max_dep_stores; st++) {
                    f->store_data_dep_mask[st] = all_inputs_mask(f);
                }
            }
            return;
        }
    }

    if (mdl_new == 0 && mds_new == 0) {
        /*
         * No slots at all: neither MEMORY block has an array to live in,
         * whatever either side said.  Where that is QEMU's own answer -- an
         * instruction with no accesses -- it is not a refusal and there is
         * no claim here to refuse; where it is a refusal it is counted as
         * one, so the cost of the honest default is a number.
         */
        if (mds_old != 0 || mdl_old != 0) {
            /* Something WAS claimed and is now unclaimed; say which. */
            unsigned r = (adm != QDEP_OK) ? adm : QDEP_NONE;
            if (r != QDEP_NONE) {
                note_refusal(mnem, r, "count", nullptr);
            }
            g_state[r].fetch_add(1, std::memory_order_relaxed);
            g_dstate[r].fetch_add(1, std::memory_order_relaxed);
        } else {
            g_state[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
            g_dstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        }
        /*
         * No store slots, so the store-data family states nothing here and
         * the destination family is the whole question.
         */
        decide_block(f, apply_dst(f, rn, q, mnem, wstate, wwhy), false, 0,
                     mnem, wstate, wwhy);
        return;
    }

    /* ---------------- the HAS_ADDR block ---------------- */
    /*
     * One mask per ACCESS, and slot k is QEMU's access k in both the count
     * and the mask.  The MULTI refusal that used to sit here -- "nothing
     * proves the k-th of one list is the k-th of the other" -- was true of
     * two lists and has no subject when there is one.
     */
    char why[64] = "";
    char dwhy[64] = "";
    uint64_t ld_mask[QDEP_MAX_ACCESS];
    uint64_t st_mask[QDEP_MAX_ACCESS];
    memset(ld_mask, 0, sizeof(ld_mask));
    memset(st_mask, 0, sizeof(st_mask));

    /*
     * WHETHER QEMU STATED **THIS ACCESS**, one answer per slot (#264).
     *
     * It used to be one answer per instruction: the first access QEMU could
     * not state refused the family, and every access it stated in full went
     * out as no block at all.  `rep stosq` is that defect with a name --
     * QEMU's own dump reads
     *
     *     M st slot=0 size=8 addr=rdi      data=rax
     *     M st slot=1 size=8 addr=rdi,@172 data=rax
     *
     * @172 being env->df, an env byte range no target declares a register
     * file for.  Slot 1's refusal deleted slot 0's `rdi`, and the wire lost
     * an address QEMU had stated in full.  R12.1 is exactly the rule that
     * forbids that: removing Capstone may not cost the trace information.
     */
    bool ld_ok[QDEP_MAX_ACCESS];
    bool st_ok[QDEP_MAX_ACCESS];
    memset(ld_ok, 0, sizeof(ld_ok));
    memset(st_ok, 0, sizeof(st_ok));

    if (state != QDEP_R_STATUS && state != QDEP_R_NORECORD) {
        /*
         * Those two say the LIST itself is unreadable, so there is no
         * per-access answer to read; every other state is one access's
         * reason and the loops below ask each slot for its own.
         */
        for (uint8_t k = 0; k < mdl_new; k++) {
            ld_ok[k] = q->load_addr_state[k] == QDEP_OK &&
                       regs_to_mask(f, q->load_addr_regs[k],
                                    q->n_load_addr_regs[k], 0, &ld_mask[k],
                                    why, sizeof(why));
        }
        for (uint8_t k = 0; k < mds_new; k++) {
            st_ok[k] = q->store_addr_state[k] == QDEP_OK &&
                       regs_to_mask(f, q->store_addr_regs[k],
                                    q->n_store_addr_regs[k], 0, &st_mask[k],
                                    why, sizeof(why));
        }
    }

    /*
     * HOW MANY of this instruction's addresses QEMU stated, and whether that
     * was all of them.  The count is the fact ESTABLISHED here, and it is
     * handed to decide_block() to be carried; @addr_all decides only whether
     * the block is wholly QEMU's or mixed.
     */
    unsigned addr_facts = 0;
    bool addr_all = mdl_new + mds_new > 0;
    for (uint8_t k = 0; k < mdl_new; k++) {
        addr_facts += ld_ok[k] ? 1u : 0u;
        addr_all &= ld_ok[k];
    }
    for (uint8_t k = 0; k < mds_new; k++) {
        addr_facts += st_ok[k] ? 1u : 0u;
        addr_all &= st_ok[k];
    }
    const bool addr_any = addr_facts != 0;
    g_addr_fact_stated.fetch_add(addr_facts, std::memory_order_relaxed);

    {
        /*
         * THE IMMEDIATE-PROVENANCE RULE, ON THE ADDRESS SIDE.
         *
         * fb92a61ea4 established it for store data: a provenance that is
         * EMPTY and COMPLETE cannot mean the value came from nowhere, and
         * the only remaining source is the instruction's own encoding, which
         * is what the format's immediate bit means.  An address is under the
         * same arithmetic -- it is computed from registers, from the
         * encoding, or from both -- so the same reading applies and this
         * settles it deliberately rather than leaving an empty address mask
         * to mean two different things depending on which shape produced it.
         * The x86-64 shape is displacement-only addressing, where the modrm
         * names no base and no index.
         *
         * COMPLETE is what makes it sound, and completeness here is not an
         * assumption: every way the provenance could have been short -- an
         * unrepresentable register, an env range with no generic word, a
         * dropped note -- is a refusal that has already sent this row to the
         * all-inputs default above, so reaching this line means QEMU stated
         * the address in full and stated no register.
         *
         * AND IT MAY FIRE ONLY WHERE NO NOTE NAMES A REGISTER, which is
         * #230's lesson written as a condition rather than as advice.  A
         * RIP-relative access has exactly this shape at the op stream --
         * gen_lea_modrm_1() folds the program counter into the displacement
         * and materialises the whole address with one movi -- and answering
         * it "immediate" would state that an address the machine derives
         * from RIP waits on nothing.  It does not reach here: the emitter
         * states the fold (insn_dataflow_note_folded_reg on cpu_eip) and the
         * row arrives with REG_PC in its mask.  A RIP-relative row appearing
         * in g_addr_imm means the note is not reaching the access -- never
         * that the rule needs an exception.
         *
         * Set only where the template HAS an immediate slot; without one
         * there is no bit to point at and the empty mask stands, which is
         * true as far as it goes.  Both halves are counted so the split is a
         * measurement.
         */
        for (uint8_t k = 0; k < mdl_new; k++) {
            if (!ld_ok[k] || ld_mask[k] != 0) {
                continue;
            }
            if (f->has_immediate) {
                ld_mask[k] = 1ULL << f->n_src_regs;
                g_addr_imm.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_addr_empty_no_imm.fetch_add(1, std::memory_order_relaxed);
            }
        }
        for (uint8_t k = 0; k < mds_new; k++) {
            if (!st_ok[k] || st_mask[k] != 0) {
                continue;
            }
            if (f->has_immediate) {
                st_mask[k] = 1ULL << f->n_src_regs;
                g_addr_imm.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_addr_empty_no_imm.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    /*
     * EVERY SLOT IS WRITTEN, from QEMU where it stated the address and from
     * the format's own all-inputs default where it did not.
     *
     * Written either way, and that is the point -- the same sentence the
     * store-data half is published under.  A slot QEMU could not state may
     * not be left carrying the refiner's mask, because a family whose source
     * has flipped may not have rows quietly holding the old one; and the
     * default is not a fabrication, it is bit-for-bit what a consumer
     * assumes when no block exists at all.  Writing on an instruction that
     * ends with no block costs nothing: the arrays are not serialised.
     */
    for (uint8_t k = 0; k < mdl_new; k++) {
        f->load_addr_dep_mask[k] = ld_ok[k] ? ld_mask[k] : all_inputs_mask(f);
    }
    for (uint8_t k = 0; k < mds_new; k++) {
        f->store_addr_dep_mask[k] = st_ok[k] ? st_mask[k] : all_inputs_mask(f);
    }

    if (!addr_all) {
        /*
         * Say which slots did not reach QEMU's answer, and why the first of
         * them did not.  A refusal is still reported by name -- the census
         * is how the population shrinks -- but it no longer decides the
         * block, and it no longer deletes the slots beside it.
         */
        unsigned r = (state != QDEP_OK) ? state : QDEP_R_UNREPRESENTABLE;
        if (addr_any) {
            for (uint8_t k = 0; k < mdl_new; k++) {
                if (!ld_ok[k]) {
                    g_addr_slot_default.fetch_add(1,
                                                  std::memory_order_relaxed);
                }
            }
            for (uint8_t k = 0; k < mds_new; k++) {
                if (!st_ok[k]) {
                    g_addr_slot_default.fetch_add(1,
                                                  std::memory_order_relaxed);
                }
            }
        }
        note_refusal(mnem, r, "addr ", why);
        g_state[r].fetch_add(1, std::memory_order_relaxed);
        (addr_any ? g_addr_blk_mixed : g_addr_blk_absent)
            .fetch_add(1, std::memory_order_relaxed);
    } else {
        g_state[QDEP_OK].fetch_add(1, std::memory_order_relaxed);
        g_addr_blk_qemu.fetch_add(1, std::memory_order_relaxed);
    }

    /* ---------------- the store-data half of HAS_REG ---------------- */

    if (mds_new == 0) {
        /* No store slot: no store_data_dep[] array exists to write, so the
         * store leg states no fact and the destinations are the whole
         * question.  This exit is the one the STATED-minus-CARRIED row
         * caught on its first run -- 3,031/1,270/1,486/1,593 facts
         * established here and never carried to a decision -- which is the
         * proof that row is a measurement and not a tautology. */
        g_dstate[dstate == QDEP_OK ? QDEP_NONE : dstate]
            .fetch_add(1, std::memory_order_relaxed);
        decide_block(f, apply_dst(f, rn, q, mnem, wstate, wwhy), false,
                     addr_facts, mnem, wstate, wwhy);
        return;
    }

    uint64_t sd_mask[QDEP_MAX_ACCESS];
    memset(sd_mask, 0, sizeof(sd_mask));
    if (dstate == QDEP_OK) {
        for (uint8_t k = 0; k < mds_new && dstate == QDEP_OK; k++) {
            if (!regs_to_mask(f, q->store_data_regs[k],
                              q->n_store_data_regs[k],
                              q->store_data_load_slots[k], &sd_mask[k],
                              dwhy, sizeof(dwhy))) {
                dstate = QDEP_R_UNREPRESENTABLE;
            }
        }
    }
    if (dstate == QDEP_OK && f->has_immediate) {
        /*
         * The stored value came from no register, no load slot and no env
         * state -- and the provenance that says so is COMPLETE, because
         * every way it could have been short is a refusal above.  A store
         * must take its datum from somewhere, so what is left is the
         * instruction's own encoding, which is exactly what the format's
         * immediate bit means.  `movq $5,(%rax)` is the shape on the
         * workload: x86 materialises an immediate operand with movi into a
         * temp of its own, so the walk sees a value with no antecedent and
         * that is the truth about it.
         *
         * `callq` USED TO REACH HERE AND MUST NOT.  Its pushed datum is the
         * return address, and eip_next_tl() folds that to tcg_constant_tl(
         * s->pc) whenever CF_PCREL is off -- the same empty-and-complete
         * shape, arriving at the same test, and answered "immediate" for a
         * value the ISA derives from RIP.  R2, R3/J2.3 and R7.3 all say a
         * QEMU fold is not the machine, so the fix is at QEMU's emitter:
         * insn_dataflow_note_folded_reg() states the instruction pointer as
         * the datum's source and the row arrives here with a non-empty mask.
         * If a direct call is ever seen taking this branch again, the note is
         * not reaching the access, not that the rule needs a call exception.
         *
         * Set only when the template HAS an immediate slot.  Pointing at a
         * slot the template says does not exist would be naming a source
         * rather than reporting one; such a row publishes the empty mask,
         * which is true as far as it goes.
         */
        for (uint8_t k = 0; k < mds_new; k++) {
            if (sd_mask[k] == 0) {
                sd_mask[k] = 1ULL << (f->n_src_regs + f->max_dep_loads);
            }
        }
    }

    /*
     * THE GATE THAT STOOD HERE IS DELETED (R12).  It read
     * `if (!f->has_reg_deps) { ...; return; }` -- the refiner's answer,
     * asked before QEMU's was known, and it threw away a store datum QEMU
     * had stated in full because Capstone had chosen not to emit a block.
     * A store datum QEMU can state IS a dependency fact, so it now CAUSES
     * the block instead of needing one to already exist.
     *
     * Written either way, and that is the point.  When QEMU stated the datum
     * the mask is QEMU's; when it could not, the mask is the format's own
     * all-inputs default written out.  What never happens is the Capstone
     * mask staying where it is -- a family whose source has flipped may not
     * have rows still quietly carrying the old one.  Writing on a row that
     * ends up with no block costs nothing: the array is not serialised.
     */
    for (uint8_t k = 0; k < mds_new; k++) {
        f->store_data_dep_mask[k] =
            (dstate == QDEP_OK) ? sd_mask[k] : all_inputs_mask(f);
    }
    if (dstate != QDEP_OK) {
        note_refusal(mnem, dstate, "sdata", dwhy);
    }
    g_dstate[dstate].fetch_add(1, std::memory_order_relaxed);
    if (dstate == QDEP_OK && mds_new > 0) {
        g_fact_stated.fetch_add(1, std::memory_order_relaxed);
    }

    /*
     * The store leg states a fact only when there is a slot to state it in:
     * `dstate` is vacuously QDEP_OK on an instruction with loads and no
     * stores, and a vacuous pass is not a fact about anything.
     */
    decide_block(f, apply_dst(f, rn, q, mnem, wstate, wwhy),
                 dstate == QDEP_OK && mds_new > 0, addr_facts,
                 mnem, wstate, wwhy);
}

void qdep_report(GString *report)
{
    uint64_t total = 0, dtotal = 0, wtotal = 0;

    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        total += g_state[s].load(std::memory_order_relaxed);
        dtotal += g_dstate[s].load(std::memory_order_relaxed);
        wtotal += g_wstate[s].load(std::memory_order_relaxed);
    }
    if (total == 0 && dtotal == 0 && wtotal == 0) {
        return;
    }

    g_string_append(report,
        "\n=== template dependencies: the source is QEMU's emitters ===\n"
        "All FOUR of the template dependency sub-block's families --\n"
        "load_addr_dep[], store_addr_dep[], store_data_dep[] and\n"
        "dst_dep[] -- are written from the provenance QEMU's own emitters\n"
        "stated: the three memory families from what each\n"
        "tcg_gen_qemu_ld/st named, and dst_dep[] from what each register\n"
        "WRITE named.  The number of SLOTS the memory families have is the\n"
        "length of that access list.\n"
        "\n"
        "A memory row this extractor cannot state IN FULL reaches the\n"
        "format's own default -- all-inputs for a mask, ZERO slots for a\n"
        "count -- and never falls back to the Capstone operand walk.  A\n"
        "DESTINATION row it cannot state keeps what the refiner wrote,\n"
        "which is the one place a Capstone answer still reaches the wire;\n"
        "it is counted by cause and by mnemonic below, because widening\n"
        "that remainder to the default is a decision that belongs with the\n"
        "numbers for it and not with the flip.\n"
        "\n"
        "WHETHER THE BLOCK EXISTS AT ALL IS ALSO QEMU'S (R12).  It exists\n"
        "when QEMU stated a dependency fact for the instruction -- a\n"
        "destination provenance or a store datum it could state in full.\n"
        "The refiner's masks are not an input to that decision.  A row QEMU\n"
        "cannot yet state publishes exactly as it did before, as a NAMED\n"
        "SURVIVOR (R12.1: removing Capstone loses NO information), listed\n"
        "below by mnemonic and by the cause that is also its coverage path.\n");

    {
        uint64_t bq = g_blk_qemu.load(std::memory_order_relaxed);
        uint64_t bs = g_blk_survivor.load(std::memory_order_relaxed);
        uint64_t bm = g_blk_mixed.load(std::memory_order_relaxed);
        uint64_t bmd = g_blk_mixed_default.load(std::memory_order_relaxed);
        uint64_t ba = g_blk_absent.load(std::memory_order_relaxed);
        uint64_t fs = g_fact_stated.load(std::memory_order_relaxed);
        uint64_t fc = g_fact_carried.load(std::memory_order_relaxed);

        g_string_append_printf(report,
            "\nthe HAS_REG block's EXISTENCE, per instruction (R12):\n"
            "  %10" G_GUINT64_FORMAT "  QEMU stated a dependency fact and the block"
            " carries it\n"
            "  %10" G_GUINT64_FORMAT "  the same, with DESTINATION slots QEMU could not"
            " state, which keep\n"
            "              the refiner's masks -- one block, two sources, and"
            " a survivor row\n"
            "  %10" G_GUINT64_FORMAT "  the same with no refiner answer either: the"
            " destination slots go out\n"
            "              as the format's own all-inputs default, written"
            " out.  Publishing the\n"
            "               array's zero initialisation instead would claim"
            " those destinations\n"
            "               depend on nothing, which is a fabrication and not"
            " a default\n"
            "  %10" G_GUINT64_FORMAT "  NAMED SURVIVORS: QEMU stated nothing this row"
            " could carry and the\n"
            "              refiner had content, so it publishes as it always"
            " did (R12.1).\n"
            "               Every one is on the coverage list below; the list"
            " shrinks, and\n"
            "               when it empties this route is deleted\n"
            "  %10" G_GUINT64_FORMAT "  no block: neither side had anything, consumer"
            " at the format's\n"
            "               own all-to-all over-approximation\n"
            "  %10" G_GUINT64_FORMAT "  QEMU facts STATED minus CARRIED -- MUST BE 0."
            "  A fact established\n"
            "              and not carried is an emission gate standing"
            " between them, which\n"
            "               is the defect R12 deleted (it read 15,763"
            " destination rows on\n"
            "               the four-ISA workload).  %" G_GUINT64_FORMAT " stated,"
            " %" G_GUINT64_FORMAT " carried\n",
            bq, bm, bmd, bs, ba, fs - fc, fs, fc);
    }

    {
        uint64_t aq = g_addr_blk_qemu.load(std::memory_order_relaxed);
        uint64_t am = g_addr_blk_mixed.load(std::memory_order_relaxed);
        uint64_t aa = g_addr_blk_absent.load(std::memory_order_relaxed);
        uint64_t ad = g_addr_slot_default.load(std::memory_order_relaxed);
        uint64_t as_ = g_addr_fact_stated.load(std::memory_order_relaxed);
        uint64_t ac = g_addr_fact_carried.load(std::memory_order_relaxed);

        if (aq || am || aa) {
            g_string_append_printf(report,
                "\nthe HAS_ADDR block's EXISTENCE, per instruction (R12,"
                " #264):\n"
                "  %10" G_GUINT64_FORMAT "  QEMU stated every access's address and"
                " the block carries them\n"
                "  %10" G_GUINT64_FORMAT "  QEMU stated SOME of them: the block exists"
                " because a stated fact\n"
                "              causes it, and the %" G_GUINT64_FORMAT " slot(s) of"
                " THOSE blocks it could not\n"
                "               state publish the format's own all-inputs"
                " default, written out --\n"
                "               bit-for-bit what a consumer assumes with no"
                " block at all.  The\n"
                "               witness is x86_64's `rep stosq`: QEMU states"
                " slot 0's address\n"
                "               as rdi and slot 1's as rdi plus an undeclared"
                " env range, and\n"
                "               the second answer used to delete the first\n"
                "  %10" G_GUINT64_FORMAT "  no block: QEMU stated no address here, so"
                " the consumer is at\n"
                "               the format's own all-to-all"
                " over-approximation.  The refiner's\n"
                "               masks are NOT published in its place --"
                " 4a104e0be4 settled\n"
                "               that, and this change does not reopen it\n"
                "  %10" G_GUINT64_FORMAT "  QEMU addresses STATED minus CARRIED --"
                " MUST BE 0.  An address\n"
                "              established and not carried is an emission"
                " gate standing\n"
                "               between them.  %" G_GUINT64_FORMAT " stated,"
                " %" G_GUINT64_FORMAT " carried\n",
                aq, am, ad, aa, as_ - ac, as_, ac);
        }
    }

    g_string_append(report, "\naddress families (HAS_ADDR):\n");
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  slots whose complete provenance named no register,"
        " published as\n"
        "              the ENCODING (displacement-only addressing; a"
        " RIP-relative row\n"
        "               here means the folded-register note is not reaching"
        " the access)\n"
        "  %10" G_GUINT64_FORMAT "  the same, on a template with no immediate slot to"
        " point at:\n"
        "               published EMPTY, which is true as far as it goes\n",
        g_addr_imm.load(std::memory_order_relaxed),
        g_addr_empty_no_imm.load(std::memory_order_relaxed));
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_state[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    g_string_append(report,
        "\nstore-data family (the HAS_REG block's store_data_dep[]):\n");
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_dstate[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    g_string_append(report,
        "\nSOURCE-SIDE MEMBERSHIP COVERAGE -- per PUBLISHED src_regs[i], is\n"
        "there a QEMU statement that justifies it?  The wire's source list is\n"
        "BUILT from this same read list (qemu_named_regs), so a JUSTIFIED\n"
        "entry is one QEMU seated and an UNJUSTIFIED one is a register only\n"
        "the operand walk supplied.  Read off QEMU's ORDERED read list, so a\n"
        "zero-register\n"
        "source and a CPUArchState-only source both count as stated -- the\n"
        "read bitmap can express neither and scoring against it would report\n"
        "every one of them as invented.\n");
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  published source entries JUSTIFIED\n"
        "  %10" G_GUINT64_FORMAT "  published source entries UNJUSTIFIED --"
        " QEMU stated the read set\n"
        "               for this instruction and this register is not in it."
        "  These\n"
        "               are the NAMED SURVIVORS the flip would have to carry"
        " (R12.1)\n"
        "  %10" G_GUINT64_FORMAT "  published source entries NOT SCORED --"
        " QEMU withheld the read\n"
        "               list for the instruction.  A THIRD outcome, never"
        " folded into\n"
        "               the line above: that would blame the wire for QEMU's"
        " refusal.\n"
        "               HONESTLY NON-ZERO, and not a must-be-0 row: this"
        " census now\n"
        "               runs BEFORE apply_dst's write-side refusal return"
        " (#327/#328),\n"
        "               so it sees the whole population.  The zero it used"
        " to print\n"
        "               was a zero about instructions it never looked at\n"
        "  %10" G_GUINT64_FORMAT "  registers QEMU reads that the wire does"
        " NOT publish -- the\n"
        "               OTHER direction, counted apart because it is what a"
        " flip would\n"
        "               GAIN and not what it would have to justify\n"
        "  %10" G_GUINT64_FORMAT "  instructions scored\n"
        "  %10" G_GUINT64_FORMAT "  instructions not scored\n"
        "  %10" G_GUINT64_FORMAT "  read lists over the fold's bound,"
        " refused rather than shortened\n",
        g_src_justified.load(std::memory_order_relaxed),
        g_src_unjustified.load(std::memory_order_relaxed),
        g_src_nostate.load(std::memory_order_relaxed),
        g_src_qemu_extra.load(std::memory_order_relaxed),
        g_src_insn_scored.load(std::memory_order_relaxed),
        g_src_insn_nostate.load(std::memory_order_relaxed),
        g_src_wide.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "\nAND THE HALF OF THE SCORE THAT IS THE TRACER'S OWN VOCABULARY.\n"
        "A member of QEMU's ordered read list this file has no generic word\n"
        "for is SKIPPED and the instruction stays scorable, so the member\n"
        "cannot justify anything -- and a source the wire publishes CORRECTLY\n"
        "is then reported UNJUSTIFIED above.  These rows say how much of the\n"
        "UNJUSTIFIED count is a QEMU statement this file could not read,\n"
        "rather than a fact QEMU never made.  A non-zero here is a COVERAGE\n"
        "PATH in the tracer's register vocabulary, not a survivor.\n"
        "  %10" G_GUINT64_FORMAT "  read-list members skipped: a TCG global"
        " with no generic word\n"
        "  %10" G_GUINT64_FORMAT "  read-list members skipped: an env byte"
        " range no declared\n"
        "               regfile names (the #226 declaration's read side)\n"
        "  %10" G_GUINT64_FORMAT "  read-list members skipped: a NAMED env"
        " field with no generic\n"
        "               word (the #218/#237 vocabulary's read side)\n"
        "  %10" G_GUINT64_FORMAT "  read-list members skipped: an entry kind"
        " this file does not\n"
        "               know -- a NEW ABI kind would land here rather than"
        " vanish\n"
        "  %10" G_GUINT64_FORMAT "  instructions with at least one skipped"
        " read-list member\n",
        g_src_skip_global.load(std::memory_order_relaxed),
        g_src_skip_field_unnamed.load(std::memory_order_relaxed),
        g_src_skip_field_generic.load(std::memory_order_relaxed),
        g_src_skip_other.load(std::memory_order_relaxed),
        g_src_skip_insns.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "\nTHE COMPOSED-REGISTER CONTAINMENT RULE (#277), and its own\n"
        "falsifier.  A published MEMBER is JUSTIFIED above when QEMU's read\n"
        "list names the CONTAINER it lives in -- mipsel's `fcr31` over the\n"
        "FCC bits, x86's `fpregs` over the x87 stack.  The rule runs in ONE\n"
        "direction: a container justifies a member, is never published, and\n"
        "never enters the QEMU-EXTRA line above.  The arms below include\n"
        "NEGATIVE cases -- a container against an unrelated register, a\n"
        "container against the slot one past its own bank, and an ordinary\n"
        "register asked to be a container -- because a rule that justified\n"
        "everything would make the zero above vacuous:\n"
        "  %10" G_GUINT64_FORMAT "  containment selftest arms run\n"
        "  %10" G_GUINT64_FORMAT "  containment selftest arms FAILED --"
        " MUST BE 0\n",
        g_cont_selftest_arms.load(std::memory_order_relaxed),
        g_cont_selftest_failed.load(std::memory_order_relaxed));
    g_string_append(report,
        "\nTHE SOURCE-LIST FLIP'S COST, measured against the survivor table\n"
        "(champsim_tracer_src_survivors.h, generated by\n"
        "tools/gen_src_survivors.py from the census above).  The flip would\n"
        "publish QEMU's ordered read list UNION the rows that table carries\n"
        "for the instruction's DECODE IDENTITY; these two rows say what that\n"
        "union is and is not, per published source entry.  MEASUREMENT ONLY:\n"
        "the wire's source list is still the operand walk's.\n");
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  published sources the union DOES NOT"
        " CONTAIN -- MUST BE 0.\n"
        "               R12.1: this is the information the flip would drop,"
        " and a\n"
        "               non-zero here is a table that does not carry its own"
        " census\n"
        "  %10" G_GUINT64_FORMAT "  registers a SURVIVOR ROW supplies that"
        " the wire does not\n"
        "               publish -- MUST BE 0.  A table row reaching an"
        " instruction that\n"
        "               does not want it is a FABRICATION, and R12.1 forbids"
        " it exactly\n"
        "               as it forbids the loss above."
        "  Scored\n"
        "               over the table's rows ALONE: the registers QEMU"
        " states and\n"
        "               the wire lacks are the QEMU-EXTRA line above and are"
        " not\n"
        "               counted twice here\n"
        "  %10" G_GUINT64_FORMAT "  instructions scored for the two rows"
        " above\n"
        "  %10" G_GUINT64_FORMAT "  of them whose decode identity has NO"
        " survivor row.  Not a\n"
        "               defect on its own -- most instructions need none --"
        " but it is\n"
        "               what says how much of the population the table was"
        " never\n"
        "               derived from\n"
        "  %10" G_GUINT64_FORMAT "  of the loss direction held back as"
        " ADJUDICATION-OWED, and\n"
        "               NOT counted in the first row above.  A published"
        " source whose\n"
        "               deletion was written, landed, measured against the"
        " external\n"
        "               references and REVERTED because they contradicted"
        " it: a\n"
        "               question in front of the maintainer, not a row"
        " nobody has\n"
        "               looked at.  It is NEVER folded into JUSTIFIED --"
        " that would\n"
        "               assert the wire is right, which is the thing not"
        " yet ruled\n"
        "               -- and no source-list flip may land while it is"
        " non-zero.\n"
        "               The rows and their questions are listed below\n"
        "  %10" G_GUINT64_FORMAT "  JUSTIFIED BY ADJUDICATION (R16) -- the"
        " same ledger, the\n"
        "               rows a RULING has closed, and NOT counted in either"
        " row above.\n"
        "               R16 verbatim: \"We record ARCHITECTURAL"
        " DEPENDENCIES.  IF THE\n"
        "               DEPENDENCY EXISTS IN THE ISA, OR THE REGISTER IS AN"
        " ISA REGISTER,\n"
        "               THEN WE RECORD IT. ... I DON'T CARE ABOUT SEMANTICS."
        "  A NOP\n"
        "               SEMANTIC STILL HAS REAL DEPENDENCIES IN THE CHOSEN"
        " REGISTER.\n"
        "               MICROARCHITECTURAL OPTIMIZATIONS SHOULD NOT BE"
        " LEAKING INTO THE\n"
        "               TRACE.  QEMU OPTIMIZATIONS SHOULD NOT BE LEAKING"
        " INTO THE TRACE.\"\n"
        "               STILL NOT FOLDED INTO JUSTIFIED, and the distinction"
        " is the point:\n"
        "               JUSTIFIED means QEMU's ordered read list contains the"
        " register,\n"
        "               which for these rows it does not.  A ruling and a"
        " read-list hit\n"
        "               are two different reasons for a row to be right, and"
        " a census\n"
        "               that spends them into one column can no longer say"
        " which rows\n"
        "               rest on a measurement and which rest on a decision."
        "  A flip may\n"
        "               land with this column non-zero -- it must carry these"
        " registers,\n"
        "               and the survivor table is where it says so.  The rows"
        " and their\n"
        "               rulings are listed below\n",
        g_src_flip_missing.load(std::memory_order_relaxed),
        g_src_flip_extra.load(std::memory_order_relaxed),
        g_src_flip_scored.load(std::memory_order_relaxed),
        g_src_flip_no_row.load(std::memory_order_relaxed),
        g_src_adj_owed_n.load(std::memory_order_relaxed),
        g_src_adj_r16_n.load(std::memory_order_relaxed));
    g_string_append(report,
        "\ndestination family (the HAS_REG block's dst_dep[]);\n"
        "every row NOT reading `PUBLISHED from QEMU's emitters` or\n"
        "`no accesses / no dataflow ABI` still carries the refiner's mask:\n");
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination SLOTS (not rows) whose complete provenance"
        " named nothing,\n"
        "              published as the ENCODING (the immediate bit); a shape"
        " whose value\n"
        "               a note should name -- the zero register, a folded"
        " register --\n"
        "               appearing here means the note is not reaching the"
        " write\n",
        g_dst_imm.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination SLOTS whose mask names registers AND"
        " ALSO takes the\n"
        "              immediate bit, because the decoder's"
        " encoded-immediate note reached them\n"
        "  %10" G_GUINT64_FORMAT "  the same shape, ABSTAINING: the note was stated, an"
        " op read the\n"
        "              value, and it did not arrive here -- the"
        " register-only mask is complete\n"
        "               and the encoding belongs to the ADDRESS"
        " (`ldr x0,[x1,#8]`)\n",
        g_dst_imm_feeds.load(std::memory_order_relaxed),
        g_dst_imm_absent.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  the same shape, COMPLETE BY THE ARCHITECTURE'S OWN"
        " DEFINITION: a decoder\n"
        "              stated that the field the encoding carries is not a"
        " dataflow operand\n"
        "               (MIPS trap and break codes), so the register-only"
        " mask is complete\n"
        "               and the row no longer claims the exception state"
        " depends on it\n",
        g_dst_imm_non_dataflow.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination SLOTS published with the DESTINATION"
        " ITSELF in their mask:\n"
        "              an accumulate, whose result depends on the"
        " destination's prior value\n"
        "               (R7/R3).  An in-place lowering's read-back and a"
        " narrow writeback's\n"
        "               preserve-read are struck out at QEMU's emitters and"
        " are not in here\n",
        g_dst_accum.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  writes to a REPRESENTATION SELECTOR, not"
        " counted as a destination:\n"
        "              a global QEMU declared as saying HOW a lowered"
        " register's other\n"
        "               globals are read, holding no part of the value"
        " (x86 cc_op).  Every\n"
        "               instruction that touches the flags writes it,"
        " including the ones\n"
        "               that only READ them, so counting it made `ja` an"
        " EFLAGS producer\n"
        "  %10" G_GUINT64_FORMAT "  writes struck as a CHANGE OF REPRESENTATION:"
        "\n"
        "              the destination is a lowered register and the whole"
        " provenance is\n"
        "               inside that register's own globals -- a value"
        " re-expressed, not\n"
        "               produced (x86 gen_compute_eflags).  R7.1's"
        " preserved bits land\n"
        "               here too, so FLAGS no longer appears in its own"
        " mask on inc/dec\n"
        "  %10" G_GUINT64_FORMAT "  wire destinations left UNNAMED by the two"
        " rules above (must be 0):\n"
        "              every stated write to a register the wire DOES carry"
        " was struck,\n"
        "               so the family refuses rather than publishing a short"
        " mask.  The\n"
        "               shape is `stc`/`clc`: materialise, then set one bit"
        " with a\n"
        "               translator constant no note separates from the"
        " materialisation\n",
        g_dst_repr_selector.load(std::memory_order_relaxed),
        g_dst_repr_change.load(std::memory_order_relaxed),
        g_dst_repr_refused.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  DISCARDED destination rows an emitter stated"
        " (#260):\n"
        "              a register the ENCODING names and the emulator throws"
        " away --\n"
        "               aarch64 `cmp`/`tst`/`cmn` writing XZR, MIPS `mul`"
        " destroying\n"
        "               HI and LO, `move $zero,$ra` translating to no op at"
        " all.  It has\n"
        "               no TCG global and no env range, so nothing but the"
        " emitter's own\n"
        "               statement can put it in QEMU's write list\n",
        g_discard_rows.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  INDEXED destination rows an emitter stated"
        " (#260):\n"
        "              a register the ENCODING names and the emulator WRITES,"
        " through an\n"
        "               index no op carries -- aarch64 FEAT_MOPS, whose helper"
        " pulls Rd,\n"
        "               Rs and Rn out of the syndrome word and addresses"
        " env->xregs[]\n"
        "               with them.  Counted apart from the line above because"
        " the write\n"
        "               HAPPENS: folding them would make that number a count of"
        " neither\n",
        g_indexed_write_rows.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  published destination families whose SLOT"
        " DICTIONARY is\n"
        "              QEMU's own write list, in QEMU's order (#232), and\n"
        "  %10" G_GUINT64_FORMAT "  families where it could NOT be -- the two lists"
        " are not the\n"
        "               same set, so no permutation of the walk's answer is"
        " QEMU's and\n"
        "               the walk's list stands.  MUST BE 0: it is the only"
        " route left by\n"
        "               which the operand walk decides which register a"
        " destination slot\n"
        "               is for\n",
        g_dst_reseated.load(std::memory_order_relaxed),
        g_dst_reseat_refused.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination rows the #236 LIST FLIP would have to"
        " REFUSE:\n"
        "              QEMU wrote an env member its own row could NOT narrow to a"
        " single\n"
        "               register, so QEMU's list is SHORT by a member it cannot name"
        " and\n"
        "               publishing it would DELETE an architectural destination."
        "  COUNTED,\n"
        "               NOT REFUSED -- nothing here changes the wire today; the row"
        " exists\n"
        "               so the flip's refusal population is a measurement.\n"
        "              THE CONDITION IS GENERAL, NOT ONE ISA'S.  It is set wherever"
        " a\n"
        "               written helper env member carries `unbounded`"
        " (accel/tcg/insn-dataflow.c,\n"
        "               the helper_writes_unbounded assignment).  aarch64 MOPS"
        " cpyfe/sete,\n"
        "               whose destination is env->xregs[mops_destreg(syndrome)], is"
        " ONE\n"
        "               instance and was the one this row was written for; x86_64"
        " also\n"
        "               carries occupants and they are NOT MOPS and are NOT yet"
        " attributed\n"
        "               per mnemonic.  Read this number as the whole unbounded-write"
        "\n"
        "               population, never as a MOPS count.\n"
        "              R12.1: the refusal is INTERIM.  Where the index is in the"
        " instruction's\n"
        "               own encoding -- as it is for MOPS -- stating it at the"
        " emitter retires\n"
        "               those rows; the rest need their own coverage path, which is"
        " why this\n"
        "               row must be attributed before the flip lands\n",
        g_dst_would_refuse_unbounded.load(std::memory_order_relaxed));
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_wstate[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    {
        uint64_t pc_only = g_dst_wire_missing_pc.load(std::memory_order_relaxed);
        uint64_t other = g_dst_wire_missing_other.load(std::memory_order_relaxed);

        g_string_append_printf(report,
            "\n  the wire's destination LIST against QEMU's writes, on the\n"
            "  rows above that PUBLISHED (the direction dst_precheck does not\n"
            "  cover -- `dst_regs[]` is the operand walk's, and a mask seated\n"
            "  on QEMU's coordinates does not change that):\n"
            "  %10" G_GUINT64_FORMAT "  QEMU wrote REG_PC and the wire's list does not"
            " carry it\n"
            "              (CORRECT BY CONTRACT per R10.1, NOT a must-be-0: a"
            " translation\n"
            "               block ends by writing the pc and QEMU charges that"
            " write to\n"
            "               whichever instruction was last, so this is the"
            " BLOCK's write,\n"
            "               not an ISA-defined one -- excluded per R1/R2/J2.3."
            "  ISA-defined\n"
            "               pc writers carry REG_PC from the operand walk and"
            " are not here.\n"
            "               The count moves with argv length, which is the"
            " proof it is an\n"
            "               artifact; the per-row adjudication is on the wire's"
            " branch_type)\n"
            "  %10" G_GUINT64_FORMAT "  QEMU wrote some OTHER named register the wire"
            " does not carry\n"
            "              (MUST BE 0 -- a destination the machine writes and"
            " the wire\n"
            "               does not name)\n", pc_only, other);
        if (other) {
            dump_tally(report, g_dst_wire_missing,
                       "  by mnemonic and register:");
        }
    }
    if (g_refusal) {
        g_string_append_printf(report, "  extractor DISABLED: %s\n", g_refusal);
    }

    g_mutex_lock(&g_tally_lock);
    dump_tally(report, g_src_skip_sig,
               "READ-LIST MEMBERS THE TRACER'S VOCABULARY DROPPED, by reason\nand name.  Each row is a fact QEMU DID state about a source that this\nfile could not carry into the score, so every published register it\nwould have justified is counted UNJUSTIFIED instead.  The reason IS the\ncoverage path: `field-word` needs a generic word, `field-range` needs an\ninsn_dataflow_declare_regfile() row, `global-word` needs a name mapping.\n`lowering` is the one reason that is NOT a coverage path -- the member is\nQEMU's own lowering state, the architecture has no such register, and\ngiving it a word would publish the emulator's internals as architecture\n(R16).  Those rows are refused CORRECTLY and nothing is owed for them:");
    dump_tally(report, g_unmapped_name,
               "globals a provenance named that have no generic word\n(per ACCESS, so an instruction refused on both an address and a datum\ncounts twice here and once above):");
    dump_tally(report, g_refusal_sig,
               "refused rows by mnemonic and reason (the format default,\nwritten out; `count` means the SLOT COUNT went to zero):");
    dump_tally(report, g_survivor_sig,
               "NAMED SURVIVORS by mnemonic and cause (R12.1) -- rows whose dep\nblock exists because the refiner had content QEMU cannot yet state.\nThe cause IS the coverage path: it names the emitter or decoder that\nhas to state the fact for the row to leave this list.  Nothing here is\ndropped, widened to a default, or refused as an endpoint:");
    dump_tally(report, g_monitor_name,
               "reservation-monitor value globals a store's datum named\n(the emulation-artefact category, #177 / f46873a738 -- NOT a decoder gap):");
    dump_tally(report, g_lowered_reg,
               "LOWERED registers on this target -- one architectural name over\nseveral TCG globals (#265).  The change-of-representation rule can only\nfire on these, so an empty list makes its zero vacuous and a non-empty\none makes the zero a result:");
    dump_tally(report, g_dst_repr_sig,
               "registers whose writes were struck as a change of representation\n(#265: the lazy-flag interpretation's subject, by generic register):");
    dump_tally(report, g_dst_repr_refused_sig,
               "registers the wire carries whose every QEMU write was struck\n(the must-be-0 above, by generic register; the mnemonic is in the\nrefusal census under QDEP_R_DST_UNNAMED):");
    dump_tally(report, g_dst_unmapped_name,
               "globals QEMU stated a WRITE to that have no generic word\n(skipped, not refused: a name the tracer's vocabulary does not contain\ncannot equal any dst_regs[d], so no mask is ever written for it):");
    dump_tally(report, g_field_unnamed,
               "env byte ranges no target declared a register file for\n(#226: the offset IS the identity, so this is a gap in QEMU's statement\nof its own layout -- never a limit of what the machine knows):");
    dump_tally(report, g_field_unmapped_name,
               "env byte ranges QEMU NAMED that have no generic word\n(#226: the name reached this file and the register table has no row for\nit -- a generator pass, not a boundary question):");
    dump_tally(report, g_src_unjustified_sig,
               "SOURCE entries the wire publishes that QEMU's read list does\nnot justify, by mnemonic and generic register.  These are the source\nhalf's NAMED SURVIVORS (R12.1): every one is published exactly as\nbefore, and each row is a coverage path -- an emitter that has to state\nthe read, or an adjudication that the wire is right and QEMU is short:");
    dump_tally(report, g_src_survivor_ident,
               "SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY -- the same\nrows as the block above, re-keyed from the disassembler's mnemonic onto\nqemu_plugin_insn_decode_id().  Columns: decode id, decode rule name,\ngeneric register, the ROLE, and the mnemonic as an ANNOTATION.  A\nsource-list flip looks a survivor up by the id, because after the flip the\nmnemonic is gone.  ROLE says how the register is reached from the id:\nFIXED means the same register on every instruction the rule decodes, SELF\nmeans the instruction's own destination register (a partial write merging\ninto what the encoding named), which no constant can stand for.  This is\nthe column tools/gen_src_survivors.py reads:");
    dump_tally(report, g_src_nostate_ident,
               "SOURCE SURVIVORS ON THE POPULATION THE CENSUS CANNOT SCORE --\nsame columns, same ROLE measurement, DIFFERENT CLAIM.  A row here is a\npublished source on an instruction whose read list QEMU withheld or\nreported short, so the census may not call it unjustified -- it may only\nsay nobody could ask.  A source-list flip still has to carry it: after the\nflip the read list supplies nothing on these instructions, so the survivor\ntable is the register's only route to the wire.  This block exists because\nNOT-SCORED was a bare count with no list behind it, and 30 of the 33\nprogram counters that lost a published source to the operand walk's\ndeletion were in it.  tools/gen_src_survivors.py reads this block too:");
    dump_tally(report, g_src_ident_witness,
               "DECODE-IDENTITY COLLISION WITNESS -- (decode id, decode rule,\nmnemonic) over EVERY row the source census is reached for, survivor or\nnot, and INCLUDING the rows whose read list QEMU refused to state.  A\ndecode id printed twice with two different mnemonics is one rule carrying\nseveral instructions (x86 clflush decodes through QEMU's NOP row), and a\nsurvivor table keyed on that id alone would hand one instruction the\nother's sources.  This is the measurement that says whether the id is a\nkey or needs qualifying, so a row missing from it is a collision nobody\nis warned about.  Its own coverage is stated and enforced below:");
    {
        uint64_t reached =
            g_src_ident_witness_reached.load(std::memory_order_relaxed);
        /* The lock is already held here -- see tally_total_locked(). */
        uint64_t printed = tally_total_locked(g_src_ident_witness);

        g_string_append_printf(report,
            "  COLLISION WITNESS COVERAGE -- the list's own completeness,\n"
            "  measured rather than claimed by its header.  Before this\n"
            "  existed the block sat inside the read-list gate while saying\n"
            "  it ran over the whole population, and every instruction whose\n"
            "  read list QEMU refused was reached and silently unlisted --\n"
            "  on the constructed x87 fixture the one row dropped was the\n"
            "  `fdivs` row a reader goes there to find:\n"
            "  %10" G_GUINT64_FORMAT "  rows REACHED (every apply_dst() row, all read-list\n"
            "              states)\n"
            "  %10" G_GUINT64_FORMAT "  rows PRINTED (the sum of the counts above, not the\n"
            "              number of distinct rows)\n"
            "  %10" G_GUINT64_FORMAT "  reached MINUS printed -- MUST BE 0.  A non-zero here is\n"
            "              a population this list did not look at, and no\n"
            "              coverage claim may be read from it while it holds.\n"
            "              The check has its own falsifier: see\n"
            "              witness_completeness_selftest(), which plants a\n"
            "              reached-but-untallied row and requires the\n"
            "              shortfall to show.\n",
            reached, printed, reached - printed);
    }
    /*
     * THE MECHANISM CORPUS'S OWN DROP COUNT.
     *
     * Reported UNCONDITIONALLY, zeros included, and with the variable unset
     * it reads a structural zero -- the writer returns before the counter on
     * a corpus nobody asked for.  A dropped row is an encoding the corpus
     * does not carry a mechanism for, and downstream that is UNREACHED and
     * therefore invisible.  A corpus whose holes are invisible is the exact
     * shape this tree keeps having to relearn, so the hole is COUNTED here
     * rather than inferred from a row count nobody compares to anything.
     */
    g_string_append_printf(report,
        "\n--- the per-encoding MECHANISM corpus (CST_SRC_MECH_DUMP) ---\n"
        "  %10" G_GUINT64_FORMAT "  rows DROPPED because the staged mechanism did not\n"
        "              name the encoding being written -- MUST BE 0.  The\n"
        "              stage is filled by qdep_apply() and read one call\n"
        "              later under the same pc; a mismatch means the\n"
        "              instruction had no dependency block at all, and the\n"
        "              row is dropped rather than printed with the previous\n"
        "              instruction's mechanism under this encoding.\n",
        g_mech_stage_mismatch.load(std::memory_order_relaxed));
    dump_tally(report, g_src_flip_missing_sig,
               "FLIP COST, THE LOSS DIRECTION -- published sources the\nsurvivor table plus QEMU's read list does NOT contain, by decode id,\nrule, register and mnemonic.  Every row here is a register a source-list\nflip would delete from the wire, which R12.1 forbids; the block is empty\nwhen the table carries its own census:");
    dump_tally(report, g_src_adj_owed_sig,
               "ADJUDICATION-OWED -- published sources the union does not\ncontain that are NOT counted as MISSING, because their deletion was\nalready written, landed, measured against the external references and\nREVERTED when the references contradicted it (PASS 29).  Columns: decode\nid, rule, register, mnemonic, and the QUESTION the row is waiting on.\nThe full evidence both ways is in exec55/QUESTIONS.md.  This block is a\nLEDGER, not a survivor table: it is keyed on the mnemonic as well as the\ndecode id (x86 0x0000054b is QEMU's NOP slot and carries endbr64 beside\nrdsspq), so no flip can look it up, and no flip may land while it has\nrows.  A row leaves this block by being RULED, never by being deleted:\nthe ruled rows are in the R16 block below, with their counts intact:");
    dump_tally(report, g_src_adj_r16_sig,
               "JUSTIFIED BY ADJUDICATION (R16) -- the same ledger, the rows\na RULING has closed.  Columns: decode id, rule, register, mnemonic, and\nthe RULING the row closed under, quoted rather than referenced so the\nreason travels with the sidecar.  These are NOT counted as MISSING and\nare NOT folded into JUSTIFIED: JUSTIFIED means QEMU's ordered read list\ncontains the register, which for these rows it does not, and a census\nthat spent a ruling and a read-list hit into one column could no longer\nsay which of its rows rest on a measurement.  A source-list flip MAY\nland with this block non-empty, and must carry every register in it:");
    /*
     * THE SURVIVOR-ROW REFUTATION, printed as the JOIN of the two tallies
     * rather than as either of them.  Runs with @g_tally_lock HELD, so it
     * reads the tables directly -- tally() takes the lock and would wedge
     * the report, which is how that split came to be named at all.
     */
    {
        uint64_t rows = 0, insns = 0, redundant = 0, short_insns = 0;
        GString *body = g_string_new(nullptr);

        if (g_surv_ref_silent_sig) {
            GList *keys = g_hash_table_get_keys(g_surv_ref_silent_sig);

            keys = g_list_sort(keys, (GCompareFunc)g_strcmp0);
            for (GList *l = keys; l; l = l->next) {
                guint sil = GPOINTER_TO_UINT(
                    g_hash_table_lookup(g_surv_ref_silent_sig, l->data));
                guint sta = g_surv_ref_stated_sig
                    ? GPOINTER_TO_UINT(g_hash_table_lookup(
                          g_surv_ref_stated_sig, l->data)) : 0;

                if (!sta) {
                    continue;   /* silent on every instance: not refuted */
                }
                guint sh = g_surv_ref_short_sig
                    ? GPOINTER_TO_UINT(g_hash_table_lookup(
                          g_surv_ref_short_sig, l->data)) : 0;

                rows++;
                insns += sil;
                short_insns += sh;
                g_string_append_printf(body,
                    "  %8u silent (%u under a SHORT read list)  %8u stated"
                    "  %s\n", sil, sh, sta, (const char *)l->data);
            }
            g_list_free(keys);
        }
        if (g_surv_ref_stated_sig) {
            GList *keys = g_hash_table_get_keys(g_surv_ref_stated_sig);

            for (GList *l = keys; l; l = l->next) {
                if (!g_surv_ref_silent_sig
                    || !g_hash_table_lookup(g_surv_ref_silent_sig, l->data)) {
                    redundant++;
                }
            }
            g_list_free(keys);
        }
        g_string_append_printf(report,
            "\nTHE SURVIVOR-ROW REFUTATION -- survivor rows scored against"
            " QEMU'S OWN\nSTATED FACTS, never against the wire.  A register a"
            " row supplies is\nrecorded as STATED when the emulator's ordered"
            " read list carries it\n(named, or inside a stated container under"
            " #277) and SILENT when it does\nnot.  Neither tally is a finding."
            "  The finding is the JOIN: a rule whose\nown emulator facts say"
            " the register on some instances and not on others is\na rule for"
            " which that register is an ENCODED OPERAND, and a SRC_SURV_FIXED"
            "\nrow claiming it on every instance FABRICATES it on the rest."
            "\n\nTHIS IS NOT g_src_flip_extra ABOVE, which is circular:"
            " qemu_named_regs()\nseats a survivor row's output into the wire"
            " before that column compares the\ntwo, so it reads zero by"
            " construction and read zero through PASS 45 while\ntwelve"
            " aarch64 SVE encodings published a predicate or a vector their"
            "\nencoding does not name.\n"
            "  %10" G_GUINT64_FORMAT "  survivor register-instances QEMU'S"
            " READ LIST STATES\n"
            "  %10" G_GUINT64_FORMAT "  survivor register-instances QEMU IS"
            " SILENT about\n"
            "  %10" G_GUINT64_FORMAT "  REFUTED ROWS -- (rule, register) pairs"
            " QEMU states on some\n"
            "              instances and not others.  MUST BE 0: the register"
            " is an\n"
            "               encoded operand and the row is not keyed on what"
            " it claims\n"
            "               to be keyed on.  The remedy is QEMU stating the"
            " operand at\n"
            "               the decode site and the row being dropped by the"
            " generator,\n"
            "               never a finer survivor key\n"
            "  %10" G_GUINT64_FORMAT "  register-instances those refuted rows"
            " FABRICATE\n"
            "  %10" G_GUINT64_FORMAT "  ... of which the instance's read list"
            " was SHORT, so the\n"
            "               register could be missing from the shortfall"
            " rather than\n"
            "               from the encoding.  Counted apart and never"
            " folded in:\n"
            "               a short list may not masquerade as a"
            " fabrication\n"
            "  %10" G_GUINT64_FORMAT "  rows QEMU states on EVERY instance --"
            " REDUNDANT, not wrong:\n"
            "               the emulator already carries the register and the"
            " row adds\n"
            "               nothing.  Reported so a table audit can retire"
            " them\n",
            g_surv_ref_stated.load(std::memory_order_relaxed),
            g_surv_ref_silent.load(std::memory_order_relaxed),
            rows, insns, short_insns, redundant);
        if (rows) {
            g_string_append(report,
                "  the refuted rows, one line each (silent instances, stated"
                " instances,\n  decode id, rule, register):\n");
            g_string_append(report, body->str);
        }
        g_string_free(body, TRUE);
    }
    /*
     * THE SECOND REFUTATION ROUTE, and it exists because the first one has
     * a population it cannot reach.  The join above needs QEMU to STATE the
     * register on at least one instance of the rule; where the emulator
     * refuses the whole read list -- riscv64 RVV, x86 scalar FMA -- every
     * instance is SILENT, the join can never fire, and the instrument would
     * report a clean 0 over exactly the rows exec86 measured as fabricating
     * on live instructions.  A zero that cannot be anything else is what
     * this whole block exists to stop reporting.
     *
     * SO THE TABLE IS ALSO READ AGAINST ITSELF, statically and without any
     * run.  SRC_SURV_FIXED means "the same register on every instruction
     * this rule decodes".  A decode id carrying TWO fixed rows from the SAME
     * NUMBERED BANK is that table saying one rule reads two different
     * vectors, or two different predicates, on every instance -- which is
     * what an ENCODED operand looks like once it has been frozen at whatever
     * the deriving corpus happened to run.  exec81 named this as the
     * generator's ready criterion; it is measured here so the count exists
     * before the generator changes.
     *
     * Singleton banks are untouched: a rule that reads one fixed vector and
     * one fixed control register says nothing suspicious, and only a
     * COLLISION inside one numbered bank is read as a refutation.
     */
    {
        unsigned isa = (unsigned)trace_isa;
        const SrcSurvivorTable *t =
            isa < G_N_ELEMENTS(g_src_survivor_tables)
                ? &g_src_survivor_tables[isa] : nullptr;
        uint64_t bank_rows = 0, bank_ids = 0, bank_reach = 0;
        GString *body = g_string_new(nullptr);

        auto bank_of = [](uint8_t r) -> int {
            if (r >= REG_GPR0  && r < REG_GPR0  + 32) return 1;
            if (r >= REG_FPR0  && r < REG_FPR0  + 32) return 2;
            if (r >= REG_VEC0  && r < REG_VEC0  + 64) return 3;
            if (r >= REG_PRED0 && r < REG_PRED0 + 32) return 4;
            return 0;   /* a singleton register is never a bank */
        };
        if (t && t->rows) {
            for (unsigned i = 0; i < t->n; i++) {
                const SrcSurvivorRow *a = &t->rows[i];
                int ba = a->kind == SRC_SURV_FIXED ? bank_of(a->reg) : 0;
                bool collides = false;

                if (!ba) {
                    continue;
                }
                for (unsigned j = 0; j < t->n; j++) {
                    const SrcSurvivorRow *b = &t->rows[j];

                    if (j == i || b->decode_id != a->decode_id
                        || b->kind != SRC_SURV_FIXED || b->reg == a->reg) {
                        continue;
                    }
                    if (bank_of(b->reg) == ba) {
                        collides = true;
                        break;
                    }
                }
                if (!collides) {
                    continue;
                }
                bank_rows++;
                /*
                 * Reach, from this run's own tallies: how many register
                 * instances the row actually supplied here.  Matched on the
                 * decode id and the register NAME, because the tally's key
                 * carries QEMU's spelling of the rule and the table carries
                 * its own annotation of it -- a row whose two spellings
                 * differ must not silently read as unreached.
                 */
                const char *rn = generic_reg_name_or_unknown(a->reg);
                char *pre = g_strdup_printf("%08x ", a->decode_id);
                uint64_t reach = 0;

                for (int pass = 0; pass < 2; pass++) {
                    GHashTable *h = pass ? g_surv_ref_stated_sig
                                         : g_surv_ref_silent_sig;
                    if (!h) {
                        continue;
                    }
                    GList *keys = g_hash_table_get_keys(h);

                    for (GList *l = keys; l; l = l->next) {
                        const char *k = (const char *)l->data;
                        size_t kl = strlen(k), rl = strlen(rn);

                        if (g_str_has_prefix(k, pre) && kl > rl
                            && g_strcmp0(k + kl - rl, rn) == 0) {
                            reach += GPOINTER_TO_UINT(
                                g_hash_table_lookup(h, k));
                        }
                    }
                    g_list_free(keys);
                }
                g_free(pre);
                bank_reach += reach;
                g_string_append_printf(body,
                    "  %8" G_GUINT64_FORMAT " reached  %08x %-26s %-12s  %s\n",
                    reach, a->decode_id, a->rule ? a->rule : "?", rn,
                    reach ? "MEASURED on a live instruction"
                          : "not reached by this run");
            }
            for (unsigned i = 0; i < t->n; i++) {
                bool first = true;

                for (unsigned j = 0; j < i; j++) {
                    if (t->rows[j].decode_id == t->rows[i].decode_id) {
                        first = false;
                        break;
                    }
                }
                if (!first) {
                    continue;
                }
                int seen[5] = {0, 0, 0, 0, 0};
                bool hit = false;

                for (unsigned j = 0; j < t->n; j++) {
                    if (t->rows[j].decode_id != t->rows[i].decode_id
                        || t->rows[j].kind != SRC_SURV_FIXED) {
                        continue;
                    }
                    int b = bank_of(t->rows[j].reg);
                    if (b && ++seen[b] > 1) {
                        hit = true;
                    }
                }
                if (hit) {
                    bank_ids++;
                }
            }
        }
        g_string_append_printf(report,
            "\nTHE SAME QUESTION ASKED OF THE TABLE'S OWN SHAPE, because the"
            " join above\nhas a population it cannot reach.  The join needs"
            " QEMU to STATE the\nregister on at least one instance; where the"
            " emulator refuses the whole\nread list -- riscv64 RVV, x86"
            " scalar FMA -- every instance is SILENT and\nthe join reads a"
            " clean 0 over rows that DO fabricate.  SRC_SURV_FIXED\nmeans"
            " \"the same register on every instruction this rule decodes\","
            " so a decode\nid carrying TWO fixed rows from ONE NUMBERED BANK"
            " is the table saying a rule\nreads two different vectors on"
            " every instance -- an ENCODED operand frozen\nat whatever the"
            " deriving corpus ran.  Singleton registers are never a bank.\n"
            "  %10" G_GUINT64_FORMAT "  decode ids whose FIXED rows COLLIDE"
            " inside one bank\n"
            "  %10" G_GUINT64_FORMAT "  rows those ids carry -- MUST BE 0."
            "  The remedy is QEMU\n"
            "               stating the encoded operand at the decode site and"
            " the row\n"
            "               being dropped by the generator, never a finer"
            " survivor key:\n"
            "               keying per (pattern, operand) is a table of the"
            " ENCODING\n"
            "               rather than of the rule\n"
            "  %10" G_GUINT64_FORMAT "  register-instances they supplied ON"
            " THIS RUN.  A row with 0\n"
            "               here is STATIC INDICATION ONLY and must be"
            " reported as\n"
            "               unreached, never as clean\n",
            bank_ids, bank_rows, bank_reach);
        if (bank_rows) {
            g_string_append(report, body->str);
        }
        g_string_free(body, TRUE);
    }
    dump_tally(report, g_src_flip_extra_sig,
               "FLIP COST, THE FABRICATION DIRECTION -- registers a\nSURVIVOR ROW supplies that the wire does not publish, by decode id, rule,\nregister and mnemonic.  A FIXED row reaching an instruction the rule\ndecodes but that does not read the register lands here, and so does a\nSELF row on an instruction whose destination is not also a source.  The\nblock is empty when every row is right for every instruction its rule\ncarries:");
    dump_tally(report, g_src_qemu_extra_sig,
               "SOURCES QEMU states that the wire does not publish, by\nmnemonic and generic register.  The OTHER direction, and not a defect\nin either list on its own -- a source the wire lacks is what a list flip\nwould add, and it is listed so the two directions stay two numbers:");
    dump_tally(report, g_dst_reseat_refused_sig,
               "DESTINATION LISTS THE RE-SEATING COULD NOT TAKE (#232: the two\nlists are not the same set, so the wire's slot dictionary is still the\noperand walk's on these mnemonics):");
    dump_tally(report, g_discard_unmapped_name,
               "DISCARDED destinations QEMU NAMED that have no generic word\n(#260: an emitter said the instruction writes a register the emulator\nthrows away and the register table has no row for that name -- a\ngenerator pass, the same shape as the line above):");
    g_mutex_unlock(&g_tally_lock);
}
