/*
 * The wire's ADDRESS dependency, taken from the emitter that stated it.
 *
 * Author: Maccoy Merrell
 *
 * WHAT THIS IS, and it is not another instrument.  champsim_tracer_irdf.cc
 * READS QEMU's dataflow and scores it against Capstone's; this file makes
 * QEMU's answer THE SOURCE of two of the wire's four dependency families --
 * `load_addr_dep_mask[]` and `store_addr_dep_mask[]`, the HAS_ADDR block of
 * the format's dependency sub-block.  Capstone's answer survives here only
 * as a shadow that is compared and counted; it does not reach the wire.
 *
 * WHY THE ADDRESS FAMILIES AND NOT ALL FOUR.  Because these are the two
 * that were measured ready, and the measurement is the reason rather than
 * the decoration.  On the four-ISA workload at the tip, QEMU's emitter-
 * stated address provenance and the Capstone operand walk agreed on
 * 32,632 of 32,632 scored accesses -- x86_64 9,256, aarch64 6,618,
 * riscv64 8,431, mipsel 8,327, zero disagreements on any ISA.  Two
 * independent derivations of one fact that agree everywhere both can speak
 * is the condition under which changing which one feeds the wire is a
 * change of SOURCE and not a change of CONTENT.  The store-DATA family is
 * not in that condition (575 rows disagree, all of them one signature) and
 * is deliberately left where it is; a half-flipped family is worse than an
 * unflipped one.
 *
 * THE FAILURE DIRECTION, which decides every rule below.  A mask that names
 * FEWER registers than really compute the address tells a consumer it may
 * issue an access before a producer has landed -- it reorders across an
 * edge the machine could not cross.  A mask that is absent tells the
 * consumer nothing and it falls back to the format's own default.  Those
 * are not symmetric, so wherever this extractor cannot state the address in
 * full it publishes NOTHING and counts the instruction.  It never publishes
 * a short mask, and it never silently falls back to the Capstone answer:
 * the fallback is the format default, by name, with a counter behind it.
 */
#ifndef CHAMPSIM_TRACER_QDEP_H
#define CHAMPSIM_TRACER_QDEP_H

#include <cstdint>

#include <glib.h>

struct qemu_plugin_tb;
struct InsnFields;

/*
 * How many distinct generic registers one access's address may depend on
 * before this extractor gives up on stating it.  Base + index + segment is
 * three on the widest addressing mode any of the four targets has; the
 * headroom is there so that a form nobody enumerated is REFUSED and counted
 * rather than silently truncated into a short mask.
 */
#define QDEP_MAX_ADDR_REGS 8

/* Why an instruction's address block is what it is.  Exactly one applies. */
enum QDepState : uint8_t {
    QDEP_NONE = 0,       /* not extracted (no dataflow ABI, or no accesses) */
    QDEP_OK,             /* QEMU stated it; the masks below are the wire's */
    QDEP_R_STATUS,       /* the extraction reported itself incomplete */
    QDEP_R_NORECORD,     /* qemu withheld the access list or a provenance */
    QDEP_R_MULTI,        /* >1 operand of a direction: slot pairing unproven */
    QDEP_R_SHAPE,        /* a direction the tracer claims that QEMU did not emit */
    QDEP_R_FIELD,        /* provenance named env state with no generic word */
    QDEP_R_UNMAPPED,     /* provenance named a global with no generic word */
    QDEP_R_WIDE,         /* more address regs than QDEP_MAX_ADDR_REGS */
    QDEP_R_UNREPRESENTABLE, /* a named reg is in no src_regs[] slot to set */
    QDEP_STATE_COUNT
};

/*
 * One instruction's emitter-stated address dependency, in the tracer's
 * GENERIC register vocabulary.
 *
 * Generic rather than slot-indexed on purpose: the src_regs[] layout a mask
 * is indexed against does not exist until decode_detail_to_generic() has
 * run, and that happens in the template builder, one call and one file
 * later.  Carrying names instead of bit positions is what lets the two
 * halves stay where each has the information it needs.
 */
struct QDepAddr {
    uint8_t state;
    bool    qemu_has_load;
    bool    qemu_has_store;
    uint8_t n_load_regs;
    uint8_t n_store_regs;
    uint8_t load_regs[QDEP_MAX_ADDR_REGS];
    uint8_t store_regs[QDEP_MAX_ADDR_REGS];
};

/*
 * Extract one instruction's address provenance at TRANSLATION time, while
 * @tb is live -- the dataflow accessors are keyed on (tb, idx) and there is
 * no later moment at which that pair still names anything.  Always safe to
 * call; writes QDEP_NONE and returns when the ABI handshake never succeeded.
 */
void qdep_note_insn(const struct qemu_plugin_tb *tb, size_t idx,
                    QDepAddr *out);

/*
 * Publish it.  Called from the template builder AFTER the operand walk and
 * any .dep_refine have run, because both of them write the very masks this
 * replaces -- dep_lea removes an address-compute's phantom load slot and
 * the x86 stack refiners add a push's implicit store slot, so a mask
 * written before them would be overwritten by them.
 *
 * Compares the Capstone-derived mask it is about to replace and counts the
 * verdict, then either writes QEMU's answer or clears has_addr_deps so the
 * consumer reaches the format's default.
 */
void qdep_apply_addr(InsnFields *f, const QDepAddr *q, const char *mnem);

/* Append the census.  Always reported: the number of instructions whose
 * address block fell back to the format default is a fact about the trace,
 * not a debugging aid, and a fact nobody prints is a fact nobody checks. */
void qdep_report(GString *report);

#endif /* CHAMPSIM_TRACER_QDEP_H */
