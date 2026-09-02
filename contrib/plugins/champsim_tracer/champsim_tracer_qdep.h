/*
 * The wire's dependency families, from the emitters that stated them.
 *
 * Author: Maccoy Merrell
 *
 * WHAT THIS IS, and it is not another instrument.  champsim_tracer_irdf.cc
 * READS QEMU's dataflow and scores it against Capstone's; this file makes
 * QEMU's answer THE SOURCE of all four of the wire's dependency families:
 *
 *   load_addr_dep_mask[]   the format's HAS_ADDR block
 *   store_addr_dep_mask[]  the format's HAS_ADDR block
 *   store_data_dep_mask[]  half of the format's HAS_REG block
 *   dst_dep_mask[]         the other half
 *
 * The first three are written from the provenance each tcg_gen_qemu_ld/st
 * emitter stated for its access; the fourth from the provenance each
 * register WRITE stated.  Capstone's answer reaches none of them on the rows
 * this file publishes.
 *
 * THE DESTINATION FAMILY IS FLIPPED FOR A NAMED POPULATION, not for all of
 * it, and the difference is stated rather than smoothed over.  Where QEMU's
 * write provenance describes a destination in full the mask is QEMU's; where
 * it does not, the row keeps what the refiner wrote and is COUNTED by cause
 * -- QDEP_R_DST_UNSTATED_CONST, QDEP_R_DST_UNNAMED, QDEP_R_DST_IMM_*, each
 * with the ruling or the missing mechanism that put it there.  That is a
 * shrinking work list with numbers attached, not a justification for the
 * remainder: qdep_report() prints every bucket on every run.
 *
 * WHY THE ADDRESS FAMILIES WENT FIRST.  Because they were the two measured
 * ready, and the measurement was the reason rather than the decoration.  On
 * the four-ISA workload the two derivations of the ADDRESS agreed on 32,632
 * of 32,632 scored accesses, zero disagreements on any ISA -- the condition
 * under which changing which one feeds the wire is a change of SOURCE and
 * not of CONTENT.  The store-DATA family was NOT in that condition: 575 rows
 * disagreed (aarch64 151, riscv64 215, mipsel 209) under exactly one
 * signature, `ir-stdata-missing:REG_ZERO`, and it was held back for it.
 *
 * WHAT DECIDED THE 575, and it is a ruling and not a discovery.  `str xzr,
 * [x0]` architecturally takes the zero register as its data operand.  QEMU
 * folds XZR / x0 / $zero to a constant before the store emitter sees it, so
 * the op stream said the stored value came from nothing.  Under R3 and J2.3
 * that fold is a QEMU optimisation and not the machine: "the regs exist even
 * if not consumed", and R7.3 is verbatim "REG_ZERO exists, so it should be
 * specified.  We should not be dropping reg zero."  The tracer was RIGHT on
 * all 575 and QEMU's answer was short.  So QEMU's answer was fixed at its
 * emitter -- insn_dataflow_note_zero_reg(), taken in cpu_reg() /
 * read_cpu_reg() / get_gpr() / get_gprh() / gen_load_gpr() /
 * gen_load_gpr_hi(), the one place the register NUMBER is still in hand --
 * rather than the ruling being worked around from the Capstone side, which
 * would re-couple exactly what this arc decouples.
 *
 * THE FAILURE DIRECTION, which decides every rule below.  A mask that names
 * FEWER registers than really feed an address or a stored value tells a
 * consumer it may issue before a producer has landed -- it reorders across
 * an edge the machine could not cross.  A mask that is the format's own
 * all-inputs default tells the consumer nothing it did not already assume.
 * Those are not symmetric, so wherever this extractor cannot state a family
 * IN FULL it publishes the default, by name, and counts the instruction.  It
 * never publishes a short mask, and it never silently falls back to the
 * Capstone answer it replaced.
 *
 * AND THE MASK IS WRITTEN IN QEMU'S OWN COORDINATES, which is a separate
 * property from the one above and was NOT true until 2026-08-26.  A mask is
 * a set of BIT POSITIONS and docs/format.rst fixes what a position means --
 * "bits [0, n_src) depends on src_reg[i]" -- so a mask whose VALUES came
 * from QEMU while its INDEXING came from the Capstone operand walk was
 * still reachable by a Capstone defect.  It was measured reachable: under
 * `QEMU_CAP_MUTATE=access`, 88 published address masks changed VALUE
 * (x86_64 60, aarch64 4, riscv64 24) because a flipped access flag moved a
 * register out of src_regs[] and shifted every later slot underneath them.
 * reindex_src_for_qemu() now seats QEMU's own register list at the head of
 * src_regs[] before any mask is written, so an address mask's bits index a
 * run whose length, order and contents QEMU alone decides.
 *
 * MEASURED AFTER, same battery, four ISAs, exec26/reindex/SCORE_address.txt:
 * load_addr_dep and store_addr_dep move 0 rows on the implicit, memdir and
 * access arms -- 0 value differences and 0 differences in the registers
 * named.  On the unmutated arm the published dependency SETS over all
 * 48,374 blocks are unchanged (SETPROOF.txt): this is a permutation of the
 * coordinate system and not a change of content.
 *
 * AND THE SLOTS ARE PER ACCESS, WHICH IS THE ADMISSION HALF.  Until
 * 2026-08-27 the mask ARRAYS were sized by `max_dep_loads` /
 * `max_dep_stores` as the Capstone operand walk counted them, and this file
 * compared QEMU's access list against that count in two gates -- a SHAPE
 * gate (a direction one side claims and the other does not) and a MULTI
 * gate (>1 operand of a direction, where nothing proved the k-th of one
 * list was the k-th of the other).  Both gates spoke Capstone's number, so
 * corrupting Capstone's operands SUPPRESSED published address blocks
 * wholesale: 8,980 of 10,272 on x86_64's access arm reached the format
 * default instead of being published.
 *
 * THE TWO LISTS WERE NEVER TWO ANSWERS TO ONE QUESTION.  Capstone counts
 * static memory OPERANDS; QEMU's memop list counts ACCESSES, one
 * tcg_gen_qemu_ld/st each.  `vmovdqu (%rax),%ymm0` is one operand and two
 * QEMU loads; `stp x0,x1,[sp]` is one operand and two QEMU stores; `lock
 * cmpxchgl` has a store the operand walk never counted.  Measured over the
 * four-ISA workload, 95 of 12,623 templates disagreed and QEMU was LONGER
 * on 91 of them.
 *
 * So the counts are QEMU's, per access, and four things follow at once:
 * the mask arrays are sized by QEMU's access count; the load-data and
 * immediate BIT OFFSETS of the register masks (`n_src + max_dep_loads`)
 * move onto that count; the decoder's runtime slot cap admits accesses
 * that had no static slot at all; and the MULTI refusal DISSOLVES, because
 * with both the count and the masks coming from ONE list the k-th pairing
 * is true by construction rather than assumed.
 *
 * WHEN QEMU CANNOT STATE THE COUNT, and this is where J7 is easiest to
 * break.  One shape: the extraction reported itself INCOMPLETE
 * (`memops_truncated` / `memops_unnoted` / a truncated provenance ->
 * QDEP_R_STATUS), or it withheld the list entirely (QDEP_R_NORECORD).  The
 * list is then not a count of anything, so the instruction reaches the
 * format's own default -- ZERO static slots, no mask array, the consumer
 * back at all-to-all with the DYNAMIC count still riding CST_FID_N_LOADS /
 * CST_FID_N_STORES -- and is COUNTED.  It never reaches back to Capstone's
 * number, which is what J7 forbids and what "leave it there and you will
 * rely on it" predicts would happen.
 *
 * `count_unbounded` IS NOT THAT SHAPE, and the first draft of this flip
 * treated it as one.  The flag says a helper repeats ONE stated access a
 * data-dependent number of times -- mipsel `swr` writes one to four bytes
 * from one base depending on the runtime alignment (target/mips/tcg/
 * ldst_helper.c:94) -- and this field has never been a bound on the DYNAMIC
 * count.  champsim_tracer_mnemonics.h says so in as many words: the static
 * caps and the wire's per-execution slot ceiling are "deliberately NOT the
 * same quantity", and x86 XSAVEOPT is ONE static store slot issuing 88
 * stores.  So an unbounded repetition is one ACCESS RECORD carrying one
 * address mask, exactly as it always was, and the repetition rides the
 * dynamic stream.  Refusing the count for it would have dropped mipsel
 * `swr`'s published store address on a stricter reading of the field than
 * the field has ever had -- measured, one row.
 *
 * WHAT THE DESTINATION FAMILY'S COORDINATE SYSTEM IS, AND WHAT IT IS NOT.
 * The paragraph above is about the bits INSIDE a mask, and it holds for
 * `dst_dep[]` as it does for the other three: `qemu_named_regs()` seats the
 * destinations' provenance into the prefix whenever the family will publish,
 * so a published destination's inputs are named in a run QEMU decides.  It
 * was MEASURED to hold -- under `QEMU_CAP_MUTATE=access`, keyed per
 * destination REGISTER, 0 of 6,035 published rows on the four-ISA workload
 * name a different input set.
 *
 * The mask ARRAY is a different question and it has a different answer.
 * `dst_dep[d]` belongs to `dst_regs[d]`, and `dst_regs[]` is the operand
 * walk's: which register a slot is for, and how many slots exist, is
 * Capstone's answer and no seating inside this file changes that.  Witnessed
 * rather than inferred -- riscv64 `c.mv` at 0x103ba, bytes `ae84`.  QEMU
 * says the write is to x9 in both arms; corrupt Capstone's operand access
 * flags and the wire's destination becomes x11, the roles of the two
 * registers exchanged.  The family then refuses (QDEP_R_DST_UNNAMED,
 * because QEMU has no write row for x11) and publishes the refiner's mask
 * for a register the instruction does not write.  On the same arm 945
 * published destinations leave the wire and 484 arrive, against 44 mask
 * movements -- so a reading that scores the whole ARRAY attributes the
 * LIST's movement to the MASK, which is the reading the first split of this
 * family took.
 *
 * That flip is the admission half for this family, the analogue of what the
 * access count became for the address families, and it is not taken here
 * because taking it would LOSE rows: replacing `dst_regs[]` with QEMU's
 * write list drops every destination QEMU names only as a CPUArchState byte
 * range, which is the env-word gap, and the failure direction forbids
 * dropping a destination the machine writes.  The other direction -- what
 * QEMU writes and the wire's list does not carry -- is counted by
 * qdep_report() and is one named class, the block-final pc write.
 *
 * THE HAS_REG FLAG IS SHARED, and that bounds both halves of it the same
 * way.  One wire bit, `CST_DEP_BLOCK_HAS_REG`, governs `dst_dep[]` AND
 * `store_data_dep[]` together (docs/format.rst).  So:
 *
 *   - `store_data_dep[]` is overwritten here whenever there is a store slot:
 *     with QEMU's mask when QEMU can state it, and otherwise with the
 *     all-inputs default written out explicitly.  No Capstone value survives
 *     in that field.
 *
 * AND THE FLAG ITSELF IS SET HERE (R12).  It used to be the refiner's, set
 * at template-construction time from Capstone's masks and read by both
 * halves of this file as a precondition -- so a fact QEMU stated in full had
 * no field to be written into unless Capstone had already decided to emit
 * one.  qdep_apply() could FILL a block; it could not CAUSE one.  Measured,
 * that inversion suppressed 15,763 QEMU-stated destination rows across four
 * ISAs, took three `rep stosq` PCs' whole block away when their refiner mask
 * collapsed to all-inputs, and left the encoded-immediate rule's decided
 * rows undeliverable.
 *
 * The rule now is: the block exists when QEMU stated a dependency fact for
 * the instruction -- a destination provenance stated in full, or a store
 * datum stated in full.  Nothing Capstone says is an input to it.
 *
 * A row QEMU cannot yet state is NOT dropped.  It publishes exactly as it
 * published before, as a NAMED SURVIVOR (R12.1: removing Capstone means zero
 * information loss), counted per mnemonic under the cause that is also its
 * coverage path.  That population is bounded, enumerated and shrinking; it
 * is not a fallback rule and it is not an endpoint.  QDEP_NO_BLOCK, which
 * used to hold the suppressed rows, is unreachable by construction, and the
 * report's STATED-minus-CARRIED row is the must-be-0 that would catch the
 * gate growing back.
 */
#ifndef CHAMPSIM_TRACER_QDEP_H
#define CHAMPSIM_TRACER_QDEP_H

#include <cstdint>

#include <glib.h>

/*
 * For QEMU_PLUGIN_DF_MAX_MEMOPS.  The ABI headers are C; every plugin TU that
 * pulls them in has to say so, or the declarations pick up C++ linkage from
 * whichever translation unit reaches them first and the .so ships mangled
 * undefined symbols.
 */
extern "C" {
#include <qemu-plugin.h>
#include <qemu-plugin-dataflow.h>
}

struct qemu_plugin_tb;
struct InsnFields;
struct InsnRegNames;

/*
 * How many distinct generic registers one access's address -- or one store's
 * datum -- may depend on before this extractor gives up on stating it.
 * Base + index + segment is three on the widest addressing mode any of the
 * four targets has, and a 128-bit store's datum is two halves; the headroom
 * is there so that a form nobody enumerated is REFUSED and counted rather
 * than silently truncated into a short mask.
 */
#define QDEP_MAX_ADDR_REGS 8

/*
 * How many ACCESSES of one direction this extractor holds per instruction.
 *
 * Not a guess, and not written down twice: it is INSN_DF_MAX_MEMOPS, the cap
 * QEMU fills the list against, so a form with more accesses than QEMU holds
 * arrives with `memops_truncated` already set and is refused one gate earlier
 * and the two caps CANNOT disagree about which instruction was refused and
 * why.  Spelling the number here is how they came to disagree: fd59da3b86
 * raised QEMU's cap 8 -> 32 and this followed; the 32 -> 48 that closed x86
 * `enter` did not, and the band 33..48 became one QEMU states whole and this
 * extractor refuses.  Measured empty at the time (aarch64 `ld4`/`st4` .16b
 * reach exactly 32, 96 encodings each, and nothing in a 9,162,613-encoding
 * sweep goes past it), which is luck, not a guarantee.
 */
#define QDEP_MAX_ACCESS QEMU_PLUGIN_DF_MAX_MEMOPS

/*
 * How many DISTINCT written registers this extractor holds per instruction.
 *
 * QEMU's own cap is INSN_DF_MAX_WRITES = 8 and a translation that exceeds it
 * arrives with `writes_truncated` already set, which the status gate refuses
 * one step earlier.  Sized to match so the two caps cannot disagree about
 * which instruction was refused and why.
 */
#define QDEP_MAX_DST 8

/*
 * How many DISTINCT generic source registers one instruction's read list may
 * carry.  Wider than QDEP_MAX_DST because the read side genuinely is: an x86
 * far call reads eight globals and two env ranges, and several globals fold
 * to one generic word, so the bound is on the folded count and not on the
 * raw one.  An instruction over it is COUNTED, never truncated -- a short
 * source list scored against the wire would report a real source as
 * unjustified and put a coverage row on a list that has no defect in it.
 */
#define QDEP_MAX_SRC 16

/* Why an instruction's dependency block is what it is.  Exactly one applies
 * per family.  The address family cannot reach QDEP_R_EMU_MONITOR (R9's
 * alias note already substitutes the guest register there); the data family
 * cannot reach QDEP_R_UNREPRESENTABLE for a load-data bit, because a store's
 * datum genuinely may be a value this same instruction loaded and the
 * HAS_REG layout HAS load-data slots to say so. */
enum QDepState : uint8_t {
    QDEP_NONE = 0,       /* not extracted (no dataflow ABI, or no accesses) */
    QDEP_OK,             /* QEMU stated it; the masks below are the wire's */
    QDEP_R_STATUS,       /* the extraction reported itself incomplete */
    /*
     * QDEP_R_SHORT -- THE READ LIST IS A LOWER BOUND, NOT A REFUSAL.
     *
     * The extraction reported itself incomplete AND QEMU still stated a
     * read list.  Those are not the same fact and until this state existed
     * the second was thrown away with the first: qdep_note_insn() returned
     * on the status word before it ever asked for the list, so an
     * instruction whose emulation runs through an unbounded helper
     * published NOTHING from QEMU no matter what QEMU said about it.
     *
     * WHY THE LIST IS STILL USABLE.  Incompleteness makes the read list
     * SHORT -- some register QEMU reads is missing from it -- and short is
     * a bound in one direction only.  Every member that IS there is a read
     * QEMU's own emitters stated, so seating it can only ADD a source the
     * wire would otherwise have to get from the operand walk.  It can never
     * remove one, and R12.1's forbidden direction is removal.
     *
     * WHAT IT MAY NOT DO, and this is why it is a separate state rather
     * than QDEP_OK.  A short list cannot adjudicate ABSENCE: "QEMU does not
     * state this register" is exactly the sentence it is not entitled to.
     * So the justification census still scores QDEP_OK alone, the survivor
     * population is unchanged, and NOT-SCORED keeps counting these
     * instructions.  The state widens what the wire PUBLISHES and narrows
     * nothing the census CONCLUDES.
     */
    QDEP_R_SHORT,
    QDEP_R_NORECORD,     /* qemu withheld the access list or a provenance */
    /*
     * QDEP_R_MULTI AND QDEP_R_SHAPE STOOD HERE, and are deleted rather than
     * left as a gap nobody can read.
     *
     * MULTI refused every instruction with more than one operand of a
     * direction because "nothing proves the k-th of one list is the k-th of
     * the other" -- true while the COUNT came from Capstone's operand walk
     * and the MASKS came from QEMU's access list.  With both from one list
     * the k-th pairing is not assumed, it is the same k, and the refusal has
     * nothing left to refuse.  SHAPE refused an instruction whose claimed
     * direction QEMU did not emit; that claim was Capstone's and is no
     * longer made.
     */
    QDEP_R_FIELD,        /* provenance named env state with no generic word */
    QDEP_R_UNMAPPED,     /* provenance named a global with no generic word */
    QDEP_R_WIDE,         /* more regs than QDEP_MAX_ADDR_REGS */
    QDEP_R_UNREPRESENTABLE, /* a named reg is in no slot to set */
    /*
     * The store-conditional lowerings hand the cmpxchg the reservation
     * monitor's VALUE half -- cpu_exclusive_val / load_val / llval -- as one
     * input of the datum it stores, because the datum genuinely is
     * `movcond(old == cmpv ? newv : old)`.  That is the emulation-artefact
     * category f46873a738 established for #177, not a decoding error and not
     * a name this extractor may invent a generic word for.  Counted apart so
     * it is never read as an ordinary unmapped-global gap.
     */
    QDEP_R_EMU_MONITOR,
    /*
     * The QEMU-owned source index could not be seated: placing QEMU's own
     * register list at the head of src_regs[] would need more slots than
     * MAX_SRC_REGS, or would push the immediate bit past bit 63.  Both
     * families are refused, because after this the coordinate system the
     * masks would be written in is still the operand walk's.
     */
    QDEP_R_REINDEX,
    /*
     * CP1.  QEMU stated that a called helper performs this access -- aarch64
     * `cpyfp` copies guest memory, mipsel `swr` stores to it -- but the
     * address (or, for the data family, the stored value) does NOT travel
     * through one of the helper's arguments, so nothing at the call site
     * names it.  The provenance QEMU hands over is EMPTY, and an empty set
     * here means "not stated", never "depends on nothing".
     *
     * Counted apart from the other refusals because it is the one that says
     * the DIRECTION is known and only the operand is not: an admission gate
     * may act on the direction, while no mask may be published.
     */
    QDEP_R_HELPER_UNSTATED,
    /*
     * DEAD BY CONSTRUCTION SINCE R12, and kept so the name of the defect
     * stays in the source.  It meant: QEMU stated the family in full, but
     * the wire's HAS_REG flag was clear -- decided earlier, by the refiner
     * -- so there was no field to write the answer into.  A QEMU fact now
     * CAUSES the block, so nothing can reach this state; the report's
     * STATED-minus-CARRIED row is the must-be-0 that says so with a number
     * that could be otherwise.
     */
    QDEP_NO_BLOCK,
    /*
     * Destination family only.  The wire has a destination slot QEMU did not
     * name as a written TCG global -- x86's vector file and x87 stack,
     * aarch64's V registers and every FP status word are CPUArchState byte
     * ranges rather than globals, and inverting an offset back to a register
     * needs a layout a plugin does not have and must not hard-code (#218).
     *
     * The whole family refuses on it rather than the one slot, because a
     * mask written for the slots that DID match would be published beside a
     * slot left carrying the answer this flip replaces, and a block whose
     * entries come from two sources is the shape nothing downstream can
     * read.
     */
    QDEP_R_DST_UNNAMED,
    /*
     * Destination family only.  A destination's provenance is EMPTY, the
     * extraction is complete, and the template carries NO immediate slot to
     * point at -- so the value is a constant this record has no word for.
     *
     * This is what is left of the class after the encoding rule above and
     * after insn_dataflow_note_zero_reg() reaches writes[].prov: the zero
     * register now arrives as a provenance BIT (R7.3, "REG_ZERO exists, so it
     * should be specified"), and an immediate arrives as the bit above.  A
     * row here is neither, and refusing is the honest answer -- publishing an
     * empty mask would state that the destination waits on nothing, which is
     * a claim nothing measured.
     */
    QDEP_R_DST_UNSTATED_CONST,
    /*
     * Destination family only.  Every destination's provenance was stated in
     * full and named at least one register, but the INSTRUCTION carries an
     * immediate -- and QEMU's provenance cannot mention one, so a mask built
     * from registers alone would be SHORT by the immediate bit.
     *
     * `add $8,%rsp` is the shape: the result is RSP plus the encoded 8, the
     * extracted set is {RSP}, and the wire's immediate bit -- which the
     * format has, and which the refiner sets -- would go dark.  496 x86_64
     * rows on the four-ISA workload when this was first measured.
     *
     * Counted apart from the empty-set gate because the two need different
     * answers: there the empty set LEAVES the encoding as the only source and
     * the slot publishes the immediate bit, here the encoding is an
     * ADDITIONAL source beside registers QEMU did name, and no reading of
     * "empty and complete" reaches it.
     */
    QDEP_R_DST_IMM_UNSTATED,
    /*
     * Destination family only, and the HALF OF QDEP_R_DST_IMM_UNSTATED THAT
     * SURVIVES THE PROVENANCE BIT.
     *
     * The encoded-immediate provenance bit (#248) answers the question above
     * wherever a decoder states it: the bit travels the dataflow, so a
     * destination that carries it depends on the encoding and one that does
     * not, does not.  This state is what is left when the decoder on this
     * instruction's path never stated the immediate at all -- QEMU reports
     * imm_stated = 0 -- and the absence of the bit therefore means "nobody
     * looked", which is not an answer.
     *
     * It is a COVERAGE hole and its size is the list of decoder paths still
     * to be reached, per mnemonic, in the refusal census.
     */
    QDEP_R_DST_IMM_UNSTATED_PATH,
    /*
     * Destination family only.  The decoder DID state this instruction's
     * encoded immediate and QEMU folded the value away before any op read
     * it -- `addi rd,rs,0` becomes a move, `andi rd,rs,0xff` becomes an
     * extract with the mask in the op's own argument rather than in a temp.
     *
     * The bit then has nowhere to travel, and its absence is the emulator's
     * optimisation rather than a fact about the machine, which R7.3 forbids
     * publishing.  Counted apart from the coverage hole above because the
     * two have different fixes: that one is reached by stating more
     * immediates, this one only by reading a fold QEMU performs before the
     * op stream exists.
     */
    QDEP_R_DST_IMM_FOLDED,
    QDEP_STATE_COUNT
};

/*
 * One instruction's emitter-stated dependencies, in the tracer's GENERIC
 * register vocabulary.
 *
 * Generic rather than slot-indexed on purpose: the src_regs[] layout a mask
 * is indexed against does not exist until decode_detail_to_generic() has
 * run, and that happens in the template builder, one call and one file
 * later.  Carrying names instead of bit positions is what lets the two
 * halves stay where each has the information it needs.
 */
struct QDepInsn {
    uint8_t state;          /* address family */
    uint8_t data_state;     /* store-data family */
    /*
     * The access list was obtained at all.  False on the two shapes where
     * QEMU said it could not tell us: the extraction reported itself
     * incomplete, or it withheld the list.  Nothing below is then readable
     * and the counts are not a MAX of anything.
     */
    bool    have_list;
    /* QEMU's ACCESS counts, in the order the target emitted them. */
    uint8_t n_loads;
    uint8_t n_stores;
    /*
     * PER ACCESS, because the wire's slot k is now QEMU's access k.  A
     * union over the accesses of a direction -- which is what this carried
     * until 2026-08-27 -- says every access of `stp x0,x1,[sp]` depends on
     * everything either of them depends on, which is true here only because
     * they share a base and is not true in general.
     */
    uint8_t n_load_addr_regs[QDEP_MAX_ACCESS];
    uint8_t load_addr_regs[QDEP_MAX_ACCESS][QDEP_MAX_ADDR_REGS];
    uint8_t n_store_addr_regs[QDEP_MAX_ACCESS];
    uint8_t store_addr_regs[QDEP_MAX_ACCESS][QDEP_MAX_ADDR_REGS];
    /*
     * AND THE VERDICT IS PER ACCESS TOO, for the same reason the register
     * lists are (#264).  @state is the FIRST refusal any access met and is
     * what the census reports; it is not a statement about the others.
     * Reading it as one refused every access of the instruction is how
     * `rep stosq` came to publish no address at all: QEMU states slot 0's
     * address as `rdi` in full and slot 1's as `rdi` plus an env byte range
     * no target declares, and the second answer deleted the first.
     *
     * QDEP_OK here means QEMU stated THIS access's address; anything else
     * names why it could not, and that slot alone reaches the format's
     * default.
     */
    uint8_t load_addr_state[QDEP_MAX_ACCESS];
    uint8_t store_addr_state[QDEP_MAX_ACCESS];
    uint8_t n_store_data_regs[QDEP_MAX_ACCESS];
    uint8_t store_data_regs[QDEP_MAX_ACCESS][QDEP_MAX_ADDR_REGS];
    /*
     * Which of THIS instruction's LOAD ACCESSES the stored datum came from,
     * one bitmap per store access.  A store's data provenance can name a
     * value the same instruction loaded -- every read-modify-write does --
     * and the HAS_REG mask has a bit per load slot to carry it, so it is
     * kept rather than refused.
     *
     * Indexed by LOAD ordinal, not by memop ordinal.  QEMU numbers the
     * load-data provenance bits by position in the WHOLE access list
     * (insn_dataflow_prov_memop), and the wire's load-data band is indexed
     * by position among the LOADS; on any instruction whose accesses
     * interleave, reading one as the other names a different slot.
     */
    uint8_t store_data_load_slots[QDEP_MAX_ACCESS];

    /*
     * THE DESTINATION FAMILY -- `dst_dep[]`, the other half of HAS_REG.
     *
     * One row per DISTINCT GENERIC register QEMU stated a write to, with the
     * inputs that write's value came from.  Generic rather than TCG-global
     * indexed because several globals stand for one architectural register
     * -- x86's cc_op / cc_dst / cc_src / cc_src2 are all REG_FLAGS -- and
     * the wire has ONE destination slot for that register, whose dependency
     * set is the union over the globals that make it up.
     *
     * A written global with no generic word is not a row: it cannot equal
     * any `dst_regs[d]`, so it can never be the slot a mask is written for.
     * It is tallied by name so the population is visible rather than
     * assumed, and the SLOT side is what decides the family -- a wire
     * destination with no row here refuses the whole instruction
     * (QDEP_R_DST_UNNAMED), which is the only direction that cannot publish
     * a short mask.
     */
    uint8_t dst_state;
    uint8_t n_dst;
    uint8_t dst_reg[QDEP_MAX_DST];              /* generic id written */
    uint8_t n_dst_dep_regs[QDEP_MAX_DST];
    uint8_t dst_dep_regs[QDEP_MAX_DST][QDEP_MAX_ADDR_REGS];
    uint8_t dst_dep_load_slots[QDEP_MAX_DST];   /* by LOAD ordinal */
    /*
     * Did the INSTRUCTION'S ENCODED IMMEDIATE reach this destination?  One
     * per destination register, because that is the question the wire asks:
     * `ldr x0,[x1,#8]` answers no for x0 and `add $5,(%rax)` answers yes for
     * the flags it writes, and both instructions carry an immediate.
     */
    uint8_t dst_dep_imm[QDEP_MAX_DST];
    /*
     * Generic registers whose EVERY stated write was a change of
     * representation, so no destination row exists for them (#265).
     *
     * Kept because the ABSENCE of a row is only correct while the wire does
     * not name the register either.  If it does, the interpretation has
     * struck out the only thing that could have filled the slot and the
     * family refuses -- which is a bounded, counted loss and a must-be-0,
     * not a silent short mask.  Without this list the refusal would be
     * indistinguishable from a register QEMU never mentioned.
     */
    uint8_t n_repr_only;
    uint8_t repr_only[QDEP_MAX_DST];

    /*
     * THE SOURCE LIST QEMU STATES, in the order the translation stated it.
     *
     * THE WIRE'S SOURCE LIST is built from this: qemu_named_regs() takes it,
     * so every register QEMU states the instruction reads is seated in
     * src_regs[].  It is also still the census's subject -- for each register
     * the wire PUBLISHES as a source, is there a QEMU statement that
     * justifies it? -- because the two questions are the same one asked from
     * opposite ends, and the census is what names the rows QEMU does not
     * state.
     *
     * Read off qemu_plugin_insn_reg_read_list(), so it carries the two kinds
     * of member the read BITMAP cannot: a CPUArchState byte range, and the
     * architectural zero register.  Scoring against the bitmap alone would
     * report every `add rd,x0,rs` zero-register source and every vector
     * source as unjustified, which is the instrument being wrong about the
     * machine rather than the wire being wrong.
     *
     * Generic ids, deduplicated, for the reason dst_reg[] is: several
     * globals stand for one architectural register and the wire has one
     * slot for it.
     */
    uint8_t src_state;
    uint8_t n_src;
    uint8_t src_reg[QDEP_MAX_SRC];

    /*
     * THE CONTAINERS THIS INSTRUCTION'S READ LIST NAMED (#277).
     *
     * A composed register is one register: the member and the container it
     * lives in are the same storage at two granularities, and #277 settled
     * that the container COVERS the member.  QEMU states the container --
     * mipsel's `bc1t` reads the whole `fcr31` because that is where the FCC
     * bit is, x86's `fxam` reads the whole `fpregs` array because that is
     * what its helper takes -- while the wire publishes the MEMBER the
     * encoding selects, and neither is wrong.
     *
     * Kept apart from src_reg[] on purpose.  These entries JUSTIFY a
     * published member and nothing else: they are never published, never
     * offered to the flip's union, and never counted as a source QEMU
     * states that the wire lacks.  Folding them into src_reg[] would let a
     * container stand IN for a member, which is the fabrication direction.
     *
     * Each row is an INCLUSIVE generic-id range, because a container covers
     * a contiguous member bank in every case measured (REG_PRED0..7 for
     * mipsel's condition codes, REG_FPR0..7 for the x87 stack).
     */
    uint8_t n_src_cont;
    uint8_t src_cont_lo[QDEP_MAX_SRC];
    uint8_t src_cont_hi[QDEP_MAX_SRC];

    /*
     * QEMU'S OWN DECODE IDENTITY for this instruction, carried so the source
     * census can key its survivor rows on it.
     *
     * The survivors -- published sources QEMU's read list does not justify --
     * are what a source-list flip has to carry across, and a table of them
     * has to be keyed on something the flip can look up at translation time.
     * That key may NOT be the mnemonic: the mnemonic is the disassembler's
     * word, which is the dependency being removed, and it is not even a
     * function of the decode (`clflush` and `nop` are one decode rule).
     * @decode_id is qemu_plugin_insn_decode_id()'s slot; @decode_name is its
     * spelling, carried for the report and never as the key.
     *
     * Whether the id ALONE separates the survivor rows is a question the
     * census answers rather than assumes -- see the collision witness in
     * qdep_report().
     */
    uint32_t decode_id;
    const char *decode_name;
    /*
     * The instruction's virtual address, carried for the PER-PC WITNESS
     * alone (CST_SRC_PC_DUMP) and read by nothing on the wire path.
     *
     * A census keyed on the decode identity can say WHICH RULE published a
     * source QEMU does not state; it can never say which instruction, and
     * an adjudication that has to be written per program counter -- the 33
     * pcs the operand walk's read arm was the only supplier for -- needs
     * the program counter.  Taken beside the identity, on the same
     * unconditional path, so a refused instruction still has one.
     */
    uint64_t insn_vaddr;

    /*
     * THE WITNESS'S TWO EXTRA FACTS.  Neither is read by anything that
     * writes a wire field; both exist because the per-pc witness had to
     * answer a question the wire path deliberately does not ask.
     *
     * @status_flags is which of qemu_plugin_insn_dataflow_status()'s
     * incompleteness bits fired, kept apart instead of folded into the one
     * refusal word.  "extraction reported itself incomplete" is six
     * different statements and they do not have one remedy: an unbounded
     * HELPER footprint is a QEMU-side note that has not been written, while
     * a truncated memop list is a bound in this file.
     *
     * @n_srcx / @srcx is QEMU's ordered read list taken WITHOUT the status
     * gate -- the list the extraction does state on an instruction whose
     * extraction also says it is short.  The wire does not use it; it is
     * here so "the read list is refused" can be told apart from "there is
     * no read list", which from the wire's side look identical and want
     * opposite answers.
     */
    uint8_t status_flags;
    uint8_t srcx_state;
    uint8_t n_srcx;
    uint8_t srcx[QDEP_MAX_SRC];
    /*
     * And the two facts that say whether a NO above is an answer.
     *
     * @imm_stated: a decoder on this instruction's path named its encoded
     * immediate at all.  @imm_reached: the value it named was read by an op,
     * so the bit had a route into the provenance.  Only with both set does
     * an absent bit mean "the encoding did not contribute"; otherwise it
     * means nobody looked, or QEMU folded the immediate away before the op
     * stream existed, and the family keeps refusing.
     */
    uint8_t imm_stated;
    uint8_t imm_reached;
    /*
     * @imm_non_dataflow: a decoder said one of this instruction's encoded
     * fields is a field the ARCHITECTURE does not define as a dataflow
     * operand -- MIPS' trap and break codes.  It is the third fact the
     * other two cannot express: without it a register-only destination on
     * such an instruction is indistinguishable from one whose immediate the
     * emulator folded away, and those want opposite answers (#252).
     */
    uint8_t imm_non_dataflow;
    /*
     * @writes_unbounded: QEMU wrote an env member its own dataflow row could
     * NOT narrow to a single register, so the write set it reports is short
     * by a member it cannot name.  749579ea65 made the CP-H reader say so
     * instead of silently reporting a short set.
     *
     * THE CONDITION IS GENERAL.  It mirrors `row->env[q].unbounded` on a
     * WRITTEN member (accel/tcg/insn-dataflow.c, the helper_writes_unbounded
     * assignment) and is not tied to any one target.  aarch64 MOPS
     * `cpyfe`/`sete`, destination `env->xregs[mops_destreg(syndrome)]`, is
     * the instance this flag was written for and the one whose coverage path
     * is known.  It is NOT the only occupant: x86_64 carries rows here too,
     * they are not MOPS, and nothing yet attributes them per mnemonic.  Do
     * not read the counter as a MOPS count -- that reading was printed in
     * the stats report and was wrong.
     *
     * IT IS NOT A REFUSAL CONDITION TODAY, and that is deliberate.  The
     * #236 LIST FLIP -- replacing the wire's `dst_regs[]` with QEMU's write
     * list -- has no honest answer for these rows: QEMU's list is short by a
     * member it cannot name, so publishing it would DELETE an architectural
     * destination, which is the one error direction this arc disqualifies.
     * The flip must REFUSE the instruction rather than publish the short
     * list, and this flag is what lets it.
     *
     * Carried and COUNTED before the flip exists so the size of that refusal
     * is a measurement rather than an estimate: g_dst_would_refuse_unbounded
     * is the population the flip's refuse route would take.  Counting it
     * changes nothing on the wire, which is exactly why it can land first.
     *
     * R12.1: a refusal is an INTERIM state and never an endpoint.  These
     * registers ARE nameable -- the index is in the instruction's own
     * syndrome, which is where QEMU reads it -- so the coverage path is to
     * state the index at the emitter and retire the refusal, not to keep it.
     */
    uint8_t writes_unbounded;

    /*
     * THE TRANSLATION'S SHAPE -- what QEMU EMITTED for this instruction,
     * as opposed to what it stated about the instruction's operands.
     *
     * WHY THE WIRE PATH DOES NOT READ IT.  None of these fields decides a
     * dependency; they exist so a SWEEP can tell whether the translation it
     * scored is the instruction's BODY at all.  An encoding whose trans_
     * function early-returns on an enable check -- SME with SMEN clear, SVE
     * trapped by CPTR, a feature the sled's context does not grant -- is
     * translated as the ACCESS TRAP and never touches an operand, yet it
     * arrives at every reader here indistinguishable from an instruction
     * QEMU translated in full and simply stated few reads for.  exec89
     * measured 38,400 aarch64 encodings of exactly that shape being scored
     * as losses; scoring a trap as an instruction is not a loss bar.
     *
     * @x_have_shape says the status read succeeded, so the four counts
     * below are readable.  It is taken BEFORE the status-refusal return,
     * because a refused extraction is exactly the population whose shape a
     * sweep most needs -- a reader that only gets the shape on the clean
     * path is blind on the rows that matter.
     *
     * @x_noreturn_calls is the load-bearing one: a call the translator
     * declared TCG_CALL_NO_RETURN is how a translation RAISES rather than
     * computes, on every target.  Read the header field's contract in
     * qemu-plugin-dataflow.h before using it -- it is a COUNT and not a
     * verdict, because an architecturally unconditional trap (`svc`, `brk`,
     * MIPS `break`) calls a noreturn helper too and for those the exception
     * IS the body.  The separation is a JOIN against the rest of the
     * instruction's dataflow, and it is made in the sweep, not here.
     */
    uint8_t x_have_shape;
    uint8_t x_calls;
    uint8_t x_noreturn_calls;
    uint8_t x_mem_reads;
    uint8_t x_mem_writes;
};

/*
 * Extract one instruction's address and store-data provenance at TRANSLATION
 * time, while @tb is live -- the dataflow accessors are keyed on (tb, idx)
 * and there is no later moment at which that pair still names anything.
 * Always safe to call; writes QDEP_NONE and returns when the ABI handshake
 * never succeeded.
 */
void qdep_note_insn(const struct qemu_plugin_tb *tb, size_t idx,
                    QDepInsn *out);

/*
 * Publish it.  Called from the template builder AFTER the operand walk and
 * any .dep_refine have run, because both of them write the very masks this
 * replaces -- dep_lea removes an address-compute's phantom load slot, the
 * x86 stack refiners add a push's implicit store slot, and every refiner
 * that sets has_reg_deps writes store_data_dep_mask[] -- so a mask written
 * before them would be overwritten by them.
 *
 * Sets the instruction's slot COUNTS from QEMU's access list first -- the
 * masks below and the register masks' load-data / immediate bit offsets are
 * all laid out against them -- then writes QEMU's answer per access, or the
 * format's default, by name, where it could not be stated.
 *
 * No comparison against what it replaces.  There was one, a shadow census of
 * the Capstone masks scored before the overwrite, and it was deleted with
 * the gates that read Capstone's counts: a path whose source has become QEMU
 * keeps no retained comparison arm, because a value still read is a value
 * still relied on.  The one-time A/B lives in this wave's evidence.
 */
void qdep_apply(InsnFields *f, InsnRegNames *rn, const QDepInsn *q,
                const char *mnem);

/* The J3 mutation arm that scores the REFINER's destination masks: run in
 * the window between the refiners and qdep_apply(), so what moves under it
 * is what the wire still takes from Capstone.  See the definition. */
void qdep_mutate_refiner_dst(InsnFields *f);

/*
 * THE PER-ENCODING READ-LIST CORPUS, env-gated (CST_SRC_ENC_DUMP=<path>).
 *
 * WHY THIS EXISTS.  `isaxcheck` scores the tracer's READ side by decoding an
 * encoding with a host tool and asking the tracer's own model what it makes
 * of the result.  That works only while the read side COMES from that
 * decode.  Where the wire's source list is QEMU's ordered read list plus the
 * survivor rows, neither is reachable from a host tool -- QEMU states the
 * read list at TRANSLATION time, inside the emulator, for the encoding being
 * translated -- so a static sweep has nothing left to compare and the
 * classes that scored the read side lose their subject rather than pass.
 *
 * So the subject is exported from the place that has it.  One row per
 * DISTINCT ENCODING -- not per program counter, because a pc-keyed gate can
 * only be replayed against the same binary at the same load address, and the
 * sweep this feeds enumerates encodings:
 *
 *   <isa>\t<encoding bytes, hex>\t<mnemonic>\t<published source registers>
 *
 * The register list is what the WIRE PUBLISHES, taken after qdep_apply() has
 * run, so it is the list a consumer reads out of the trace -- not an
 * intermediate, and not a re-derivation that could drift from one.
 *
 * IT SEES THE WRONG PATH, and that is the point rather than a side effect.
 * Every standing per-pc source instrument in this tree runs at wp=0, so an
 * instruction only the wrong path translates is outside all of them.  A
 * corpus taken at wp=0 AND wp=16 covers both, and the first time it was run
 * it found twenty encodings a wp=0 bar had just reported clean.
 *
 * MEASUREMENT ONLY and OFF unless asked for: with the variable unset the
 * site is a single relaxed load, and no wire field is written here ever.
 */
void dump_src_enc_row(const InsnFields *f, const uint8_t *bytes,
                      uint8_t size, const char *mnem);

/*
 * THE PER-ENCODING OPCODE-CLASS CORPUS, env-gated (CST_OPC_ENC_DUMP=<path>).
 *
 *   <isa>\t<encoding bytes, hex>\t<mnemonic>\t<GenericOpcode name>
 *
 * WHY IT IS A SECOND CORPUS AND NOT A COLUMN ON THE FIRST.  The read-list
 * corpus is a gate's subject: srcenc_loss_gate compares two arms and fails
 * on a register leaving the wire.  Widening its row would move the file
 * shape under every reader that already parses it, and the two corpora are
 * not asked for together -- a source A/B does not want to pay for an
 * opcode census and a class A/B does not want the register lists.
 *
 * WHY IT EXISTS AT ALL.  Nothing in this tree watches `.opcode`.  SETPROOF
 * scores register SETS; srcenc scores READ LISTS; the identity census counts
 * rows and tiers.  PASS 45 stated the consequence plainly: no loss
 * instrument here can see an opcode-class move, so a change that reclassifies
 * an encoding -- GEN_OP_INT_ADD becoming GEN_OP_UNKNOWN, or becoming
 * GEN_OP_INT_SUB -- passes every standing bar.  That is the precise gap the
 * QID_STATED admission has to cross: 86.7% of the identity rows state an
 * opcode that `qemu_ident_classify()` currently refuses to publish, and
 * admitting them moves the wire's opcode column with no instrument watching.
 *
 * THE CLASS IS TAKEN AFTER qdep_apply(), at the same site and off the same
 * InsnFields as the read list, so it is the class the template packs and a
 * consumer reads out of the trace -- not an intermediate, and not a
 * re-derivation that could drift from one.
 *
 * IT SEES THE WRONG PATH for the same reason the read-list corpus does, and
 * the capture takes wp=0 and wp=16 for the same reason: an encoding only the
 * wrong path translates is outside every per-pc instrument in this tree.
 *
 * MEASUREMENT ONLY and OFF unless asked for: with the variable unset the
 * site is a single relaxed load, and no wire field is written here ever.
 */
void dump_opc_enc_row(const InsnFields *f, const uint8_t *bytes,
                      uint8_t size, const char *mnem);

/*
 * THE PER-ENCODING MECHANISM CORPUS, env-gated (CST_SRC_MECH_DUMP=<path>).
 *
 *   <isa> <encoding hex> <mnemonic> <decode_id> <decode rule> <src_state>
 *   <wstate> PUB QN SURV RD STATUS RDX CONT XLAT WR
 *
 * XLAT and WR say what the TRANSLATION WAS, where every column before them
 * says what QEMU stated about the operands of one.  See QDepInsn's
 * @x_have_shape block: an encoding whose trans_ function early-returns on an
 * enable check is translated as the access trap and reads, on every other
 * column, exactly like an instruction with few stated reads.
 *
 * WHY A THIRD CORPUS.  The read-list corpus (dump_src_enc_row) says WHAT an
 * encoding publishes; an A/B over two builds says WHICH registers the
 * operand walk is the only supplier of.  Neither says WHY QEMU did not
 * supply them, and "why" is the whole question a fix has to answer: a
 * register missing because the read list was REFUSED needs a different
 * repair from one missing because QEMU stated a complete list that simply
 * does not mention it.  Those are the two mechanisms, they need opposite
 * work, and no instrument in this tree could tell them apart per encoding.
 *
 * The columns are the PER-PC witness's columns (dump_src_pc_row), keyed on
 * the ENCODING instead of the program counter, because the loss population
 * lives in the space no guest executes -- the sled reaches it and a pc does
 * not name it.  Identical column meanings on purpose: a reader written for
 * one file reads the other, and the two can be joined where they overlap.
 *
 * WHY NOT A COLUMN ON THE READ-LIST CORPUS.  Same answer as the opcode
 * corpus: srcenc_loss_gate parses that file's fourth column and fails a
 * build on it.  Widening a gate's subject to carry a diagnostic is how a
 * gate stops meaning what its name says.
 *
 * MEASUREMENT ONLY and OFF unless asked for: with the variable unset the
 * site is a single relaxed load, the staging slot is never filled, and
 * neither qemu_named_regs() nor src_survivor_regs() is called for it.
 */
/* Whether that corpus is taking rows.  Public because the STAGING of a
 * mechanism answer happens one call earlier than the row is written, in
 * qdep_apply(), and neither qemu_named_regs() nor src_survivor_regs() may be
 * walked on the translation path for an instrument nobody asked for. */
bool src_mech_corpus_live(void);

void dump_src_mech_row(uint64_t pc, const InsnFields *f, const uint8_t *bytes,
                       uint8_t size, const char *mnem);

/* Append the census.  Always reported: the number of instructions whose
 * dependency block fell back to the format default is a fact about the
 * trace, not a debugging aid, and a fact nobody prints is a fact nobody
 * checks. */
void qdep_report(GString *report);

#endif /* CHAMPSIM_TRACER_QDEP_H */
