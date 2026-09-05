/*
 * ENCODING FIELDS A SURVIVOR ROW MAY BE KEYED ON.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHAT THIS IS FOR.  champsim_tracer_src_survivors.h keys each row on
 * qemu_plugin_insn_decode_id() -- QEMU's decode RULE -- and then has to say
 * how the register is reached from that rule.  Two answers existed:
 *
 *   FIXED   the register is a property of the RULE.  `ret` reads SS.
 *   SELF@p  the register is a property of the INSTANCE and the wire already
 *           publishes it, at destination slot p.
 *
 * NEITHER IS TRUE OF THE MSA CLASS, and that is what this file is for.  MIPS
 * `xori.b $w16,$w14,imm` publishes REG_VEC14 as a source QEMU does not state,
 * and REG_VEC14 is neither a property of `translate_mips/OPC_MDMX` -- the next
 * instance reads $w21, and the one after $w19 -- nor a destination of its own
 * instruction, which is $w16.  It is the value of the `ws` FIELD of the
 * instruction word.  A FIXED row keyed on the rule would publish the deriving
 * corpus's operand on every MSA instruction forever; gen_src_survivors.py's
 * REFUSAL 6 already refuses to write one, which left the class with no key at
 * all.  This is that key: the register NUMBER is read from a NAMED FIELD of
 * the instruction's own encoding, and the row carries the bank it indexes.
 *
 * THE FIELD SET IS AN ARCHITECTURAL FACT, NOT A MEASUREMENT, so it is written
 * here with its citation rather than generated.  What IS measured is which
 * field (if any) a survivor's register number matches, on every instance the
 * census scores -- see the ROLE column in champsim_tracer_qdep.cc.  A field
 * this table does not define can never appear in a role, and a role naming a
 * field this table does not define is refused by the generator, which parses
 * THIS FILE for the legal names so the two cannot drift.
 *
 * A FIELD IS DEFINED ONLY AT ONE INSTRUCTION WIDTH.  @insn_bytes is part of
 * the definition, not a guard bolted on: `ws` is bits 15:11 OF A 32-BIT MIPS
 * WORD, and extracting those bits from a 2-byte or 6-byte encoding is reading
 * a different instruction's operand.  An encoding of any other width matches
 * no field, so the role falls back to the answer that needs no encoding.
 *
 * THE WORD IS ASSEMBLED LITTLE-ENDIAN from the instruction bytes, which is
 * what the tracer's mipsel target is.  A big-endian MIPS guest would need its
 * own rows here rather than a byte-swap at the extraction site: the field
 * definition is per (isa, width) and the endianness belongs to the isa.
 */
#ifndef CHAMPSIM_TRACER_ENC_FIELDS_H
#define CHAMPSIM_TRACER_ENC_FIELDS_H

#include <stdint.h>

#include <glib.h>

#include "champsim_tracer_generic_ids.h"

/*
 * The field ids.  `SRC_ENC_FIELD_NONE` is 0 so a zeroed row is a row naming
 * no field, and the generator emits it for every kind that is not
 * SRC_SURV_ENC.
 */
typedef enum {
    SRC_ENC_FIELD_NONE = 0,
    SRC_ENC_FIELD_MIPS_WS,
    SRC_ENC_FIELD_MIPS_WT,
    SRC_ENC_FIELD_MIPS_WD,
    SRC_ENC_FIELD__COUNT,
} SrcEncFieldId;

/*
 * ONE INSTRUCTION'S ENCODING, carried down to the dependency model.
 *
 * The model is handed FIELDS, never the instruction -- that is deliberate and
 * it is why the per-encoding corpora are dumped one level up, in
 * create_tb_template().  The ENC role is the one question the fields cannot
 * answer: "is this register the value of a field of the instruction word?"
 * has no term without the word.  So the bytes travel as ONE parameter, const
 * and non-owning, and every consumer treats an empty one as "cannot tell"
 * rather than as a fact -- @bytes is NULL wherever the caller has no encoding
 * (a wrong-path synthetic, a caller outside the translation path), and a
 * NULL encoding matches no field, so a row that needs one contributes
 * nothing instead of contributing a guess.
 */
typedef struct {
    const uint8_t *bytes;
    uint8_t        len;
} InsnEnc;

typedef struct {
    uint8_t     id;          /* SrcEncFieldId */
    uint8_t     isa;         /* TraceISA */
    uint8_t     insn_bytes;  /* the width the field is DEFINED at */
    uint8_t     lsb;
    uint8_t     width;
    uint8_t     bank_base;   /* the generic id the field's value indexes  */
    uint8_t     bank_n;      /* how many registers that bank has          */
    const char *name;        /* the spelling the ROLE column prints       */
} SrcEncFieldDef;

/*
 * MIPS MSA (MSA32 rev 1.12, tables 3.2-3.5).  Every MSA format that names a
 * vector register places it in the same three fields of the 32-bit word:
 *
 *     wt = 20:16    ws = 15:11    wd = 10:6
 *
 * verified against the tree's own MSA fixture, `nori.b $w1,$w25,0x10` =
 * 0x7810c85e: bits 15:11 = 25 ($w25, the source), bits 10:6 = 1 ($w1, the
 * destination), bits 23:16 = 0x10 (the immediate).  The I8 formats have no
 * wt -- their bits 23:16 are the immediate -- so a role naming `wt` on an I8
 * encoding is a numeric coincidence and the census's ambiguity report is what
 * catches it, not a per-format table here: the census scores a field against
 * an OBSERVED register number, and a format table would let this file decide
 * an answer the measurement is supposed to give.
 */
static const SrcEncFieldDef g_src_enc_fields[] = {
    { SRC_ENC_FIELD_MIPS_WT, TRACE_ISA_MIPS, 4, 16, 5, REG_VEC0, 32, "wt" },
    { SRC_ENC_FIELD_MIPS_WS, TRACE_ISA_MIPS, 4, 11, 5, REG_VEC0, 32, "ws" },
    { SRC_ENC_FIELD_MIPS_WD, TRACE_ISA_MIPS, 4,  6, 5, REG_VEC0, 32, "wd" },
};

/* The little-endian word an @n-byte encoding spells, or false if @n is not
 * a width any field is defined at. */
static inline bool src_enc_word(const uint8_t *bytes, uint8_t n, uint8_t want,
                                uint32_t *out)
{
    if (!bytes || n != want || want == 0 || want > 4) {
        return false;
    }
    uint32_t v = 0;
    for (uint8_t i = 0; i < want; i++) {
        v |= (uint32_t)bytes[i] << (8 * i);
    }
    *out = v;
    return true;
}

/* The definition for @id, or NULL.  Linear over three rows; this is not a
 * hot path and a table indexed by the enum would go stale silently. */
static inline const SrcEncFieldDef *src_enc_field_def(uint8_t id)
{
    for (unsigned i = 0; i < G_N_ELEMENTS(g_src_enc_fields); i++) {
        if (g_src_enc_fields[i].id == id) {
            return &g_src_enc_fields[i];
        }
    }
    return NULL;
}

/*
 * The generic register @d's field selects out of THIS encoding, or REG_NONE.
 * REG_NONE is returned for every reason a caller must not distinguish by
 * guessing: the wrong ISA, the wrong width, no bytes, or a field value past
 * the end of the bank.
 */
static inline uint8_t src_enc_field_reg(const SrcEncFieldDef *d,
                                        unsigned isa,
                                        const uint8_t *bytes, uint8_t n)
{
    uint32_t w;

    if (!d || d->isa != isa || !src_enc_word(bytes, n, d->insn_bytes, &w)) {
        return REG_NONE;
    }
    uint32_t v = (w >> d->lsb) & ((1u << d->width) - 1u);

    if (v >= d->bank_n) {
        return REG_NONE;
    }
    return (uint8_t)(d->bank_base + v);
}

#endif /* CHAMPSIM_TRACER_ENC_FIELDS_H */
