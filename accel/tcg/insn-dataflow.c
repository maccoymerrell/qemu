/*
 * Per-instruction dataflow, derived from the IR the target's translator
 * emitted.
 *
 * This supplies dataflow only.  Identifying the instruction -- mnemonic,
 * opcode class, branch class, length -- stays with the decoder, permanently;
 * nothing here can say which instruction it is looking at and nothing here
 * tries.
 *
 * The premise is the same one that makes memory instrumentation work: a guest
 * instruction's accesses are not something to be looked up, they are
 * something QEMU has already written down.  A memory access is an explicit
 * TCG op; so is a register access.  Every op declares how many of its
 * arguments are outputs and how many are inputs, and a temp that is
 * TEMP_GLOBAL based on tcg_env is a guest register at a known offset in
 * CPUArchState.  Walking the ops between two insn_start markers and sorting
 * the global temps by argument position gives the read and write sets of one
 * instruction, from the machine's own translation of it.
 *
 * Why before tcg_optimize()
 * -------------------------
 * Dead-store elimination removes architecturally real writes that nothing
 * downstream consumes.  x86 is the extreme case: the whole lazy-flags scheme
 * exists so that a flag write can be dropped when the next instruction does
 * not look at them.  So this runs at the end of translator_loop(), before any
 * pass has touched the ops and before the plugin's translate callback needs
 * the answer.
 *
 * What it gives that a state differ cannot
 * ---------------------------------------
 * Reads, at all.  Inert writes -- tcg_gen_movcond_* names its destination as
 * a plain output, so a conditional move's write is in the IR whether or not
 * the condition made it a no-op, and a consumer modelling speculative
 * register release needs to know it happened.  And writes whose value equals
 * what was already there, which are invisible to anything that compares
 * state before and after.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op-common.h"
#include "tcg/tcg-internal.h"
#include "exec/insn-dataflow.h"
/*
 * For dh_typecode_ptr.  The typemask a helper carries is built out of these,
 * so reading it with the same names the builder used is the only way the two
 * cannot drift; a local `#define DF_TYPECODE_PTR 6` would compile forever
 * after the encoding changed.
 */
#include "exec/helper-head.h.inc"

/*
 * TCG's own cap on instructions per TB.  A TB cannot hold more, so the result
 * array never needs to grow and never needs to be allocated per translation.
 */
#define INSN_DF_MAX_INSNS   512

#define INSN_DF_NOT_ENV     INT64_MIN

/*
 * Emitter notes.
 *
 * Three choke points state facts the op list does not carry: CP4 the operands
 * a gvec constructor folded away, CP-M which temp of a memop is the data and
 * which the address, CP-H a helper's logical argument list.  All three are
 * anchored on a TCGOp, so the instruction walk attributes a note to whichever
 * instruction's op range contains its anchor and no op numbering is needed.
 *
 * They live in the per-context scratch and not at file scope.  Under MTTCG
 * two vCPUs translate at the same time in two TCGContexts, so a file-scope
 * note array is written by both and read as though it belonged to one -- the
 * exact aliasing the scratch's own comment says it exists to avoid.
 */
#define DF_MAX_GVEC_NOTES     64
#define DF_MAX_MEMOP_NOTES    64
/*
 * Address aliases stated by an emitter (insn_dataflow_note_addr_alias).
 * One per store-conditional, and a TB that reaches sixty-four of them has
 * far more pressing problems; past that the notes stop and the accesses
 * taken after are marked unnoted rather than silently short.
 */
#define DF_MAX_ALIAS_NOTES    64
/*
 * Zero-register operands stated by an emitter (insn_dataflow_note_zero_reg).
 * One per zero-register operand an instruction reads, PER INSTRUCTION -- the
 * note carries an anchor and is deduplicated against it, so a TB of nothing
 * but `add a0,a1,x0` takes one note per instruction rather than one for the
 * whole block.  Sized for the block: INSN_DF_MAX_INSNS instructions, two
 * zero-register operands each (`addu rd,$zero,$zero` is the shape that needs
 * two).  Past the cap the notes stop, a store taken after is marked unnoted
 * rather than published with its data operand missing, and a WRITE taken
 * after is reported as an incomplete extraction rather than published with
 * an empty provenance that would read as "came from nowhere".
 */
#define DF_MAX_ZERO_NOTES     1024
/*
 * Discarded-write notes (insn_dataflow_note_discarded_write).  One per
 * destination an instruction names and the emulator throws away.  AArch64
 * reaches this most often -- every `cmp`, `tst` and `cmn` in a block takes one
 * -- so it is sized like the zero-register cap rather than like the handful
 * of emitters that state the others.  Past the cap the notes stop and the
 * overflow flag makes the extraction incomplete, because a destination list
 * that is SHORT is the one error direction this file treats as an error.
 */
#define DF_MAX_DISCARD_NOTES  1024
/*
 * Folded-register operands stated by an emitter (insn_dataflow_note_folded_reg).
 * One per such operand a block resolves.  Two emitters state them, both x86's:
 * eip_next_tl(), once per call instruction, and gen_lea_modrm_1(), once per
 * RIP-relative memory operand -- which position-independent code reaches far
 * more often than it calls, so the cap is sized for the address half.  Past it
 * the notes stop and an access taken after is marked unnoted rather than
 * published with its source missing.
 */
#define DF_MAX_FOLD_NOTES     512
/*
 * Folded-READ notes (insn_dataflow_note_folded_read).  One per source register
 * an instruction's encoding names and the emitter resolved at translation
 * time, PER INSTRUCTION -- the note carries an anchor and is deduplicated
 * against it, so a block of nothing but conditional branches takes one note
 * per branch rather than one for the block.  Sized like the zero-register
 * notes: INSN_DF_MAX_INSNS instructions, one or two such operands each.  Past
 * the cap the notes stop and the read list would be SHORT by a source the
 * encoding named, so the overflow refuses the list rather than shortening it.
 */
#define DF_MAX_ENCREAD_NOTES  1024
/*
 * Encoded-immediate operands stated by a decoder
 * (insn_dataflow_note_encoded_imm).  One per immediate operand an
 * instruction names, PER INSTRUCTION -- the note carries an anchor and is
 * deduplicated against it, so a block of nothing but `addi rd,rs,8` takes
 * one note per instruction rather than one for the block.  Sized like the
 * zero-register notes and for the same reason: INSN_DF_MAX_INSNS
 * instructions, a couple of immediate operands each.  Past the cap the notes
 * stop and every instruction after is reported with imm_stated = 0, which is
 * the "nobody said" state a consumer must refuse on rather than the "it did
 * not contribute" state it must not infer.
 */
#define DF_MAX_IMM_NOTES      1024
/*
 * Preserve-reads stated by a WRITEBACK emitter
 * (insn_dataflow_note_preserve_read).  One per partial write an instruction
 * performs, PER INSTRUCTION -- the note names the op that has just consumed
 * the background, so a block of nothing but `setne %al` takes one note per
 * instruction.  Sized like the zero-register notes.  Past the cap the notes
 * stop, and the instructions after it report their preserve-read as an
 * ordinary operand read: pessimistic -- an edge nothing needs -- rather than
 * a source that goes missing, which is the direction this file may not take.
 */
#define DF_MAX_PRESERVE_NOTES 1024
#define DF_MAX_VALUE_NOTES    1024
/*
 * Representation carriers.  One per lowered register a target caches in a
 * temp, stated once per translation -- x86 has exactly one, and no other
 * target in the tree has any.  Four is room for a target that lowers more
 * than one register that way.
 */
#define DF_MAX_CARRIER_NOTES  4
#define DF_MAX_HELPER_NOTES   64
#define DF_MAX_HELPER_ARGS    8
/*
 * A row's env footprint can be much longer than the argument list -- x86's
 * helper_cpuid reaches twenty members of CPUArchState -- so the staging
 * arrays are sized for the footprint, not for the arguments.
 */
#define DF_MAX_HELPER_FIELDS  32

typedef struct DfGvecNote {
    const TCGOp *anchor;
    uint32_t dofs, aofs, bofs, oprsz;
} DfGvecNote;

typedef struct DfMemopNote {
    const TCGOp *anchor;
    const void *val_ts;
    unsigned nval;              /* consecutive temps the value occupies */
    const void *addr_ts;
    unsigned size;
    bool is_store;
    int rec;                    /* which memop record this note filled, or -1 */
    /*
     * How many address aliases had been stated when this note was taken.
     * Resolution searches only those, newest first, so an alias states a fact
     * about the accesses that FOLLOW it and about no others -- two
     * store-conditionals in one TB cannot borrow each other's address.
     */
    unsigned alias_n;
    bool alias_dropped;         /* an alias was lost to overflow before this */
    /*
     * The same scoping for the zero-register notes: how many had been stated
     * when this note was taken.  A store's data temp is looked for only among
     * those, so an operand read AFTER this access cannot retro-name its data.
     */
    unsigned zero_n;
    bool zero_dropped;          /* a zero note was lost to overflow before this */
    /*
     * And again for the folded-register notes, for the same reason: a
     * constant an emitter resolves AFTER this access cannot name its
     * operands.
     */
    unsigned fold_n;
    bool fold_dropped;          /* a fold note was lost to overflow before this */
    /*
     * The note this one is a SECOND EMISSION of, or -1.  Set inside an
     * alternate-path scope (insn_dataflow_note_path_alt): the two emissions
     * are ONE architectural access lowered onto mutually exclusive code
     * paths, so this note fills @alt_of's record instead of allocating one.
     */
    int alt_of;
} DfMemopNote;

/*
 * CP-M, the folded-register half: one temp an emitter is handing on in place
 * of an architectural register it did not read, and the TCG global for that
 * register.  Unlike the zero register this one HAS a global, so the fact is
 * stated in the ordinary provenance namespace and needs no bit of its own.
 */
typedef struct DfFoldNote {
    const void *ts;
    const void *src_ts;
    /*
     * The op that had just DEFINED @ts when the note was taken, or NULL when
     * @ts is a constant, which no op defines and nothing can redefine.
     *
     * A note is a claim about a temp's CURRENT contents, and x86's address
     * generation writes every address into one temp that lives for the whole
     * block (DisasContext::A0).  Without the anchor, one RIP-relative access
     * would name the instruction pointer for every later access in the same
     * TB whose address happens to land in the same temp -- a fabricated
     * dependency, which is worse than the missing one this closes.  The walk
     * records each temp's defining op as it goes and df_fold_add_srcs()
     * accepts the note only while the two still agree.
     */
    const TCGOp *anchor;
} DfFoldNote;

/*
 * CP-M, the folded-READ half: one architectural register an instruction's
 * encoding names as a source, for which the emitter produced no temp at all.
 * The register is what is carried -- there is nothing else to carry, which is
 * the difference from DfFoldNote above.
 */
typedef struct DfEncReadNote {
    /*
     * The TCG global for the register, or NULL for the ZERO-REGISTER form,
     * which has no global on any target that has the register -- the whole
     * reason it needs a form of its own.
     */
    const void *src_ts;
    /*
     * The op the stating emitter had produced when the note was taken, which
     * bounds the note to ONE instruction under the same cursor discipline the
     * zero-register and immediate notes run under.  Without it the first `je`
     * in a block would name the instruction pointer as a source of every
     * instruction after it.
     */
    const TCGOp *anchor;
    uint8_t zero;
    /*
     * The CPUArchState-RANGE form, for a register the instruction reads that
     * has no TCG global AND no temp -- because the emulator resolved the read
     * at TRANSLATION time and left no op behind at all.  @env_size is 0 for
     * the two forms above and non-zero for this one, which is what tells them
     * apart; @env_off is only meaningful when it is set.
     */
    uint32_t env_off;
    uint32_t env_size;
    /*
     * The NAME form, for a register that has no global, no temp AND no env
     * range -- AArch64's ARM_CP_CONST system registers live in ARMCPU, not
     * CPUArchState.  Non-NULL for that form alone, and it is checked BEFORE
     * @env_size so the three forms stay mutually exclusive by construction.
     */
    const char *name;
} DfEncReadNote;

/*
 * CP-M, the address half: one temp an emitter will pass as an access address,
 * and the temp in the guest's own namespace that it has just proved equal.
 */
typedef struct DfAliasNote {
    const void *alias_ts;
    const void *real_ts;
} DfAliasNote;

/*
 * CP-M, the zero-register half: one temp an emitter is handing on in place of
 * the architectural zero register, and the op the emitter had last produced
 * when it said so.
 *
 * THE ANCHOR IS WHAT MAKES THE NOTE A FACT ABOUT ONE INSTRUCTION.  On RISC-V
 * the accessor hands back `ctx->zero`, which is `tcg_constant_tl(0)` -- the
 * same interned temp every constant zero in the block resolves to.  A note
 * carrying only that temp says "somewhere in this TB a zero register was
 * read", which is enough for the memop path, where the note is searched over
 * the prefix taken before an access and the only way a store's data temp can
 * BE that constant is for its data operand to have been the zero register.
 *
 * It is NOT enough for a register WRITE.  Every instruction writes something,
 * and on any target a constant zero reaches an ordinary op for reasons that
 * have nothing to do with the zero register.  Without an anchor the first
 * `add a0,a1,x0` in a block would put the zero register in the provenance of
 * every later write in it -- a fabricated dependency, and the one error
 * direction this extractor may not take.  The anchor is the op the emitter
 * had produced when the note was taken, so the walk can bound the notes to
 * the instruction whose op range reached them, exactly as the memop cursor
 * bounds its own.
 */
typedef struct DfZeroNote {
    const void *ts;
    const TCGOp *anchor;
} DfZeroNote;

/*
 * CP-M, the discarded-write half: one destination the ENCODING names, the
 * name it has in the target's own namespace, and the temp whose end-of-
 * instruction contents are the value it receives.
 *
 * The anchor is the op the emitter had last produced, exactly as DfZeroNote's
 * is, and it is load-bearing for the same reason turned around: AArch64's
 * cpu_reg(s, 31) hands out a FRESH temp per call, but a block full of `cmp`s
 * takes one note apiece and the walk has to give each to its own instruction.
 */
typedef struct DfDiscardNote {
    const void *ts;
    const char *reg;            /* NULL when @zero says which register */
    bool zero;
    /*
     * The accessor could not say whether this use is a read or a write, so
     * the walk decides: a later op of this instruction writing @ts is the
     * architectural write, and @anchor being still its definition means the
     * temp was only ever the constant the accessor put in it.  See
     * insn_dataflow_note_zero_write_holder().
     */
    bool holder;
    /*
     * The emulator PERFORMS this write, through an index only the encoding
     * states.  See insn_dataflow_note_indexed_write(); part of the note key
     * for the same reason @reg is, so a target that states both about one
     * temp keeps two statements.
     */
    bool by_index;
    const TCGOp *anchor;
} DfDiscardNote;

/*
 * CP-M, the encoded-immediate half: one temp a DECODER is handing on as the
 * value the instruction's encoding names, and the op the emitter had last
 * produced when it said so.
 *
 * THE ANCHOR IS LOAD-BEARING HERE FOR A SHARPER REASON THAN IT IS FOR THE
 * ZERO REGISTER.  Immediates are small integers and tcg_constant_tl() interns
 * by value, so a TB of ordinary integer code resolves every `8` in it -- the
 * displacement of one instruction, the shift count of another, the mask a
 * third's lowering needed -- to a single temp.  A note carrying only that
 * temp would put the ENCODING in the provenance of every later write that
 * touched an 8 for a reason of QEMU's own, which is a fabricated dependency
 * on a source that does not exist.  The anchor bounds the note to the
 * instruction whose op range reached it, exactly as DfZeroNote's does.
 */
typedef struct DfImmNote {
    /*
     * The temp the emitter materialised the field into, or NULL for the
     * VALUE-STATING form -- the field that never becomes a temp at all.
     * See insn_dataflow_note_encoded_imm_value() in the header.
     */
    const void *ts;
    const TCGOp *anchor;
    /*
     * Value form only.  @role is one of INSN_DF_IMM_ROLE_*, and 0 on a
     * temp-form note, whose role the temp itself already carries: it is an
     * operand, because an emitter materialised it to be read.
     */
    uint64_t value;
    uint8_t role;
} DfImmNote;

/*
 * CP-M, the preserve-read half: one READ of a guest register that an emitter
 * performed only to carry the bits its write does not touch.
 *
 * THE PAIR IS THE FACT, and it is (temp, CONSUMING op) rather than (temp,
 * anchor of the last op) as every other note here is.  A preserve-read is a
 * property of ONE ARGUMENT OF ONE OP -- `deposit cpu_regs[EAX],
 * cpu_regs[EAX], t0, 0, 8` reads EAX as background -- and the same
 * instruction can read the same global as a genuine operand in a different
 * op: `add %al,%bl` fetches BL through `ext8u t0, cpu_regs[EBX]` and then
 * writes back through a deposit whose background is cpu_regs[EBX] again.
 * A note scoped to the instruction would strike out both and lose the
 * architectural edge; scoped to the op, it strikes out exactly the one the
 * emitter said was a preserve.
 *
 * WHY THE EMITTER AND NOT THE OP SHAPE.  `deposit d, d, x, pos, len` is the
 * same three ops for AArch64's MOVK, which the architecture DOES define as
 * reading Xd, and for x86's byte-register writeback, which R7.1 rules does
 * not make RAX a source.  Nothing in the op list separates them; the
 * emitter knows which one it is writing, because one is the decoder
 * resolving an operand and the other is a writeback helper preserving bits
 * the instruction never named.  So the fact is stated there, once, at the
 * writeback -- and its ABSENCE leaves the read exactly as it was, which is
 * the pessimistic direction: a missing note publishes an edge nothing
 * needs, never drops one something does.
 */
typedef struct DfPreserveNote {
    const void *ts;
    /*
     * The op range the emitter produced, exclusive of @mark and inclusive of
     * @end.  A RANGE and not a single op because tcg_gen_deposit_*() is not
     * always one op: the host backend takes it whole when it can, and expands
     * it into and/shift/or when it cannot -- and then the read of the
     * background is in the FIRST op of the expansion while the last op is the
     * one the emitter can name.  MIPS's `mtc1` is the measured case, where
     * `deposit_i64 f,f,t,0,32` is not a valid host deposit and the note keyed
     * on the last op alone silently matched nothing.
     *
     * @mark is NULL when the emitter had produced no op at all, which means
     * the range starts at the first op of the block.
     */
    const TCGOp *mark;
    const TCGOp *end;
} DfPreserveNote;

/*
 * A REPRESENTATION CARRIER: a temp holding a redundant spelling of a value
 * one of the guest's own registers already carries.  See
 * insn_dataflow_note_repr_carrier() in the header.
 *
 * @stands_for is kept as the GLOBAL'S INDEX rather than as a pointer, because
 * that is the namespace the read set and the provenance are written in and
 * resolving it once per translation costs nothing.
 *
 * @defined_here is the instruction boundary, and it is what keeps the note
 * from deleting real edges: it says an op of the instruction CURRENTLY being
 * walked has already written the carrier, so a read of it is that write's
 * value and not the previous instruction's.  Cleared at the top of every
 * instruction; see df_insn().
 */
typedef struct DfCarrierNote {
    const void *ts;
    unsigned stands_for;
    bool defined_here;
} DfCarrierNote;

/* CP-H: one per helper call, carrying what tcg_gen_callN had and the op lost. */
typedef struct DfHelperNote {
    const TCGOp *anchor;
    const char *name;                       /* TCGHelperInfo::name */
    uint32_t flags;                         /* TCGHelperInfo::flags */
    const TCGTemp *arg[DF_MAX_HELPER_ARGS];
    uint8_t typecode[DF_MAX_HELPER_ARGS];
    uint8_t nargs;
    bool args_overflow;                     /* more logical args than we carry */
    /* Roles the gvec constructor stated for this same call, if it was one. */
    bool has_gvec;
    unsigned gvec_n;
    uint32_t gvec_off[INSN_DF_MAX_GVEC_OPERANDS];
    uint8_t gvec_dir[INSN_DF_MAX_GVEC_OPERANDS];
    uint32_t gvec_oprsz;
} DfHelperNote;

/*
 * One member of CPUArchState a helper reaches, and in which direction.
 *
 * This is what answers the OTHER half of the opacity, and it is the larger
 * half.  A helper handed tcg_env can touch all of CPUArchState and the call
 * says nothing about which of it -- helper_fsin(env) has no other argument at
 * all.  So the members are enumerated, from the helper's own body, and the
 * enumeration is what makes the footprint bounded.
 */
typedef struct DfHelperField {
    uint32_t off;
    uint32_t size;
    uint8_t dir;
    /*
     * Whether this access is an OPERAND of the guest instruction, or a read
     * THE EMULATOR MAKES ON ITS OWN BEHALF.
     *
     * helper_lookup_tb_ptr's only CPUArchState reads are
     * cpu_get_tb_cpu_state(), which computes the key QEMU looks the next
     * translation up by: on riscv64 that is vtype, vl, vstart, misa_ext,
     * menvcfg, priv and xl.  Publishing those as reads of the branch that
     * chained would tell a consumer that `ret` depends on the vector type
     * register, which is not true of the guest machine and is a fabricated
     * edge -- and eleven of them per branch overran INSN_DF_MAX_FIELDS on
     * every chained branch, measured: riscv64's truncation count went 0 ->
     * 383 the first time this row shipped without the distinction.
     *
     * THE TRANSLATION KEY IS NOT THE ONLY SUCH READ, and saying it was is
     * what let the second kind through.  An exception-raise path records
     * the faulting address (x86 `env->exception_next_eip = env->eip + ...`,
     * riscv's trace point on env->pc), and aarch64's BTI check probes the
     * attributes of the page the instruction was FETCHED from by handing
     * `env->pc` to is_guarded_page().  Those are the emulator saying WHERE
     * it is, not the instruction computing a value -- and the last of them
     * was measured putting REG_PC on the wire as a source of
     * `ccmp x0,x1,#0,eq`, which reads no program counter in any mode.  The
     * usage table's generator selects them by the SOURCE LINE the reader
     * read the member off, so a helper reaching the same line is covered
     * without anyone remembering to name it, and helper_syscall's read of
     * `env->eip` -- which becomes RCX, and IS an operand -- is not.
     *
     * They are still ENUMERATED, because a row that omitted them would be
     * claiming a footprint it had not accounted for.  They are not
     * PUBLISHED, because the wire carries operands.
     */
    uint8_t kind;
    /*
     * The ARRAY INDEX was not stated in the source.
     *
     * `env->xregs[mops_destreg(syn)]` is a write to one general register and
     * the source does not say which, so the range recorded here is the whole
     * file.  Such a range REACHES PAST a register and is therefore named as
     * none of them -- correctly, since calling it the first would publish a
     * set short by thirty-one.  The bit exists so a consumer can tell that
     * apart from a range that simply has no declared owner: this one is a
     * write QEMU DID account for and could not narrow, which is a fact about
     * the instruction rather than a gap in anybody's table.
     */
    uint8_t unbounded;
} DfHelperField;

#define DF_HF_OPERAND   0
/*
 * Not an operand: the emulator's own read.  Named XLAT for the first member
 * of the class -- the TB lookup key -- and it now also carries the
 * exception-raise path's record of the faulting address and the BTI check's
 * probe of the fetched page.  The name is kept because it is the column's
 * wire-visible spelling in four generated tables and renaming it would move
 * audit rows for a fact that has not changed.
 */
#define DF_HF_XLAT      1

/*
 * CP1.  One class of guest memory access a helper performs ITSELF.
 *
 * "Class" and not "access": the row is keyed by (direction, address
 * argument), because that is the pair the call site states and the count is
 * frequently not statable at all.  helper_swr stores between one and four
 * bytes depending on the address's alignment, so its row says WR through
 * argument 2, one byte at a time, count unbounded -- and says the count is
 * unbounded rather than writing down 4, which is a property of the source
 * text and not of any execution.
 */
typedef struct DfHelperAccess {
    uint8_t dir;                /* INSN_DF_RD, INSN_DF_WR, or both */
    uint8_t addr_arg;           /* LOGICAL argument carrying the address */
    uint8_t data_arg;           /* LOGICAL argument carrying a stored value */
    uint8_t size;               /* bytes per access; 0 = not stated */
    uint8_t count_unbounded;    /* how MANY is data-dependent */
} DfHelperAccess;

/* The address (or data) does not travel through an argument at all. */
#define DF_HA_NO_ARG    0xff

typedef struct DfHelperUsage {
    const char *name;
    /*
     * Per LOGICAL argument: the direction of that pointer argument, or 0 for
     * "not stated".  Indexed by the helper's own parameter position, counting
     * tcg_env if it takes one -- the same numbering hn->arg[] uses.
     */
    uint8_t argdir[DF_MAX_HELPER_ARGS];
    /*
     * Per LOGICAL argument: the EXTENT in bytes of the state that pointer
     * reaches, or 0 for "not stated".  It is sizeof() the type the helper's
     * own definition declares the parameter to point at.
     *
     * The gvec constructors state their operands' width at the call site and
     * nothing stated it for anyone else, so every non-gvec pointer argument
     * arrived here with extent 0 -- and a range of unstated width names no
     * register, which is why `movsd`'s and `punpcklqdq`'s XMM destinations
     * reached the wire with no QEMU write row behind them.  The gvec figure
     * still wins where it exists: it is the width of THIS call, while this
     * is the width of the parameter's type.
     */
    uint16_t argsize[DF_MAX_HELPER_ARGS];
    /* The footprint through tcg_env, complete when @env_bounded. */
    const DfHelperField *env;
    uint8_t n_env;
    /*
     * True when @env is the WHOLE footprint: every CPUArchState member the
     * helper reads or writes, on the path that returns.  A row is only
     * written when the reader closed the body, so a row that exists says
     * this; a helper the reader refused has NO ROW and stays opaque.
     */
    bool env_bounded;
    const char *src;            /* where the row was read from */
    /*
     * The guest memory this helper reaches.  NULL/0 means the reader found
     * no access in the body it closed -- which for a row that exists is a
     * measurement, since a row is only written when the body closed.
     */
    const DfHelperAccess *acc;
    uint8_t n_acc;
} DfHelperUsage;


/*
 * Per-translation scratch.
 *
 * It belongs to the TCGContext, which is the object whose lifetime and
 * exclusion it needs: one context per translating vCPU in system mode, and
 * in user mode the single tcg_init_ctx every guest thread shares while
 * holding the translation lock.  translator_loop() is not re-entrant on a
 * context, so one set per context is enough and none of it needs a lock of
 * its own.  Keying on the context rather than the thread also makes this
 * agree with the accessor guard in plugins/api.c, which decides whether a
 * result is still readable by comparing against tcg_ctx->plugin_tb.
 *
 * It is emphatically NOT a thread-local.  At 376 KiB it is far too large for
 * static TLS, which is charged to every thread the process creates -- vCPU,
 * iothread, RCU, and every guest thread -- whether or not that thread ever
 * translates anything, and which glibc places INSIDE the stack allocation
 * pthread_create is handed, so a static TLS block approaching a guest
 * thread's stack size makes clone(2) fail outright (see do_fork() in
 * linux-user/syscall.c).
 *
 * The generation counter is what keeps this cheap.  Clearing a provenance
 * table of TCG_MAX_TEMPS entries at the top of every TB is kilobytes of memset
 * on a path that runs for every translation in the program; stamping each
 * entry with the translation it belongs to and treating a stale stamp as empty
 * costs one comparison on first touch and nothing at all for a temp the TB
 * never uses.
 *
 * slot_off interns env byte ranges no TCG global names, for the duration of
 * one translation block, so they can carry provenance bits alongside the
 * globals.  A TB touches very few distinct ones; overflow stops interning,
 * which is the safe direction -- see df_intern().
 */
struct InsnDataflowScratch {
    uint32_t gen;
    uint32_t stamp[TCG_MAX_TEMPS];
    uint64_t prov[TCG_MAX_TEMPS][INSN_DF_REG_WORDS];
    int64_t envoff[TCG_MAX_TEMPS];
    /*
     * The op that last wrote each temp, as the walk passes it.  Only the
     * folded-register notes read it, and only to ask whether the temp still
     * holds what the note described.  Same generation stamp as prov[] and
     * envoff[], so a temp the block never writes reads back as NULL.
     */
    const TCGOp *defop[TCG_MAX_TEMPS];

    InsnDataflow out[INSN_DF_MAX_INSNS];
    unsigned ninsns;

    uint32_t slot_off[INSN_DF_MAX_FIELD_SLOTS];
    /*
     * The WIDEST access seen at that offset in this translation.
     *
     * A bit is interned by offset alone -- two accesses that start at the
     * same byte are the same state -- but NAMING one needs its extent, and
     * an offset on its own says nothing about how far the access reached.
     * Widening rather than keeping the first is the direction that cannot
     * mis-name: a helper handed the WHOLE vector file starts at the same
     * byte as a store of its first register, and only the extent tells the
     * two apart.  DF_FIELD_UNBOUNDED stands for a reach nothing stated.
     */
    uint32_t slot_size[INSN_DF_MAX_FIELD_SLOTS];
    unsigned nslots;
    bool slots_overflow;

    DfGvecNote gvec[DF_MAX_GVEC_NOTES];
    unsigned n_gvec;
    bool gvec_overflow;

    DfMemopNote memop[DF_MAX_MEMOP_NOTES];
    unsigned n_memop;
    bool memop_overflow;
    /*
     * The open alternate-path scope: which note the emissions inside it
     * mirror, and how many have been taken.  @alt_open is false everywhere
     * but inside the peeled copy of a self-looping string operation.
     */
    bool alt_open;
    unsigned alt_mark;
    unsigned alt_taken;

    DfAliasNote alias[DF_MAX_ALIAS_NOTES];
    unsigned n_alias;
    bool alias_overflow;

    /*
     * CP-M, the zero-register half: the temps three targets' accessors hand
     * back in place of a register the encoding named.  Pointers only -- there
     * is one architectural zero register per target, so which one it is never
     * has to be carried.
     */
    DfDiscardNote discard[DF_MAX_DISCARD_NOTES];
    unsigned n_discard;
    bool discard_overflow;

    DfZeroNote zero[DF_MAX_ZERO_NOTES];
    unsigned n_zero;
    bool zero_overflow;

    /*
     * CP-M, the folded-register half: the temps an emitter handed on in place
     * of a register it computed away.  Pairs rather than pointers, because
     * which register it stood for is exactly what has to be carried.
     */
    DfFoldNote fold[DF_MAX_FOLD_NOTES];
    unsigned n_fold;
    bool fold_overflow;

    /*
     * CP-M, the folded-READ half: the registers an encoding names as sources
     * for which no temp was ever made.  The absence of a temp is the whole
     * reason the note exists.
     */
    DfEncReadNote encread[DF_MAX_ENCREAD_NOTES];
    unsigned n_encread;
    bool encread_overflow;

    /*
     * CP-M, the encoded-immediate half: the temps a decoder handed on as the
     * value its encoding names.  Pointers plus an anchor, no value: which
     * immediate it was is the guest's business and the wire's immediate bit
     * carries no payload.
     */
    DfImmNote imm[DF_MAX_IMM_NOTES];
    unsigned n_imm;
    bool imm_overflow;

    /*
     * CP-M, the preserve-read half: the (temp, op) pairs a writeback emitter
     * marked as carrying only the bits its write does not reach.
     */
    DfPreserveNote preserve[DF_MAX_PRESERVE_NOTES];
    unsigned n_preserve;
    bool preserve_overflow;

    /*
     * The (temp, op-range) pairs an emitter marked as SUPPLYING a value --
     * the same note shape as the preserve half above and read the same way.
     * See insn_dataflow_note_supplied_value().
     */
    DfPreserveNote value[DF_MAX_VALUE_NOTES];
    unsigned n_value;
    bool value_overflow;

    /*
     * The temps a target declared as carrying a lowered register's value.
     * No overflow flag: the array is sized above what any target in the tree
     * declares, and a declaration that did not fit would be reported by the
     * carrier fold reading 0 on an ISA whose stats say it declared one.
     */
    DfCarrierNote carrier[DF_MAX_CARRIER_NOTES];
    unsigned n_carrier;

    DfHelperNote helper[DF_MAX_HELPER_NOTES];
    unsigned n_helper;
    bool helper_overflow;
};

/*
 * The scratch for the translation in progress.
 *
 * Cached in a (pointer-sized) thread-local so the per-op accessors below cost
 * a load rather than a dereference chain.  insn_dataflow_extract() refreshes
 * it from tcg_ctx before anything reads it, allocating on the first
 * translation this context performs; the read-side entry points at the bottom
 * of the file are the ones a plugin can reach, and they treat a NULL scratch
 * as "nothing extracted", which is what a caller that arrives before any
 * translation must be told.
 */
static __thread struct InsnDataflowScratch *df;

#define df_gen              (df->gen)
#define df_stamp            (df->stamp)
#define df_prov             (df->prov)
#define df_envoff           (df->envoff)
#define df_defop            (df->defop)
#define df_out              (df->out)
#define df_ninsns           (df->ninsns)
#define df_slot_off         (df->slot_off)
#define df_slot_size        (df->slot_size)
#define df_nslots           (df->nslots)
#define df_slots_overflow   (df->slots_overflow)
#define df_gvec             (df->gvec)
#define df_n_gvec           (df->n_gvec)
#define df_gvec_overflow    (df->gvec_overflow)
#define df_memop            (df->memop)
#define df_n_memop          (df->n_memop)
#define df_memop_overflow   (df->memop_overflow)
#define df_alt_open         (df->alt_open)
#define df_alt_mark         (df->alt_mark)
#define df_alt_taken        (df->alt_taken)
#define df_alias            (df->alias)
#define df_n_alias          (df->n_alias)
#define df_alias_overflow   (df->alias_overflow)
#define df_discard          (df->discard)
#define df_n_discard        (df->n_discard)
#define df_discard_overflow (df->discard_overflow)
#define df_zero             (df->zero)
#define df_n_zero           (df->n_zero)
#define df_zero_overflow    (df->zero_overflow)
#define df_fold             (df->fold)
#define df_n_fold           (df->n_fold)
#define df_fold_overflow    (df->fold_overflow)
#define df_encread          (df->encread)
#define df_n_encread        (df->n_encread)
#define df_encread_overflow (df->encread_overflow)
#define df_imm              (df->imm)
#define df_n_imm            (df->n_imm)
#define df_imm_overflow     (df->imm_overflow)
#define df_preserve         (df->preserve)
#define df_n_preserve       (df->n_preserve)
#define df_preserve_overflow (df->preserve_overflow)
#define df_value            (df->value)
#define df_n_value          (df->n_value)
#define df_value_overflow   (df->value_overflow)
#define df_carrier          (df->carrier)
#define df_n_carrier        (df->n_carrier)
#define df_helper           (df->helper)
#define df_n_helper         (df->n_helper)
#define df_helper_overflow  (df->helper_overflow)

/*
 * Bind @df to the current translation context, allocating on first use.
 *
 * The generation starts at 1 and the stamps start at 0, so every entry reads
 * as stale until the translation that touches it says otherwise -- the same
 * initial state the static allocation this replaced was given.
 */
static void df_bind(void)
{
    struct InsnDataflowScratch *s = tcg_ctx->insn_df;

    if (unlikely(s == NULL)) {
        s = g_malloc0(sizeof(*s));
        s->gen = 1;
        tcg_ctx->insn_df = s;
    }
    df = s;
}

/*
 * Give @off a provenance bit, above the globals.
 *
 * When the table is full this returns -1 and the caller records nothing,
 * which makes a value that came from this field look as though it came from
 * nowhere.  That is the direction that must never be taken lightly and is
 * taken here only because the alternative is worse: see the note on
 * df_field_prov() about which way an error in this code should fall.  With 64
 * slots against the handful of distinct fields any real instruction touches,
 * the case is not reachable in practice, and df_slots_overflow says so out
 * loud when it is.
 */
static int df_intern(uint32_t off, uint32_t size)
{
    unsigned base = tcg_ctx->nb_globals;
    uint32_t reach = size ? size : DF_FIELD_UNBOUNDED;

    /*
     * KEYED BY OFFSET AND EXTENT, not by offset alone.
     *
     * Two accesses that start at the same byte and reach different distances
     * are different accesses, and the extent is the only thing that says
     * which register the range belongs to: `movaps %xmm0,(%rdi)` reads 16
     * bytes at offsetof(xmm_regs) and a helper handed the whole vector file
     * reads 2048 at the same byte.  Folding them onto one slot forces one
     * extent on both, and the only safe choice then is the wider -- which
     * costs the narrow access its name for the rest of the block.  Measured:
     * merging cost six x86_64 store-data rows their register.
     *
     * Two slots for one offset is not a contradiction downstream.  A
     * consumer resolves each to the register it belongs to and unions, so
     * the same register arrives once however many bits named it.
     */
    for (unsigned i = 0; i < df_nslots; i++) {
        if (df_slot_off[i] == off && df_slot_size[i] == reach) {
            return (int)(base + i);
        }
    }
    if (df_nslots >= INSN_DF_MAX_FIELD_SLOTS ||
        base + df_nslots >= INSN_DF_IMM_PROV_BIT) {
        df_slots_overflow = true;
        return -1;
    }
    df_slot_size[df_nslots] = reach;
    df_slot_off[df_nslots] = off;
    return (int)(base + df_nslots++);
}

/*
 * Measurement scaffolding.  The extraction is meant to be unconditional in a
 * production build, so the only way to say what it costs is to be able to run
 * the same binary without it: QEMU_DF_OFF makes it return immediately, which
 * is the baseline every reported figure is against.  QEMU_DF_PROFILE reports
 * the extraction's own time, and both are read once.
 */
static bool df_off, df_off_read;
static bool df_prof, df_prof_read;
static int64_t df_prof_tbs, df_prof_insns, df_prof_ops, df_prof_ns;
static int64_t df_prof_every = 20000;

static int64_t df_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void df_prof_dump(void)
{
    if (!df_prof_tbs) {
        return;
    }
    fprintf(stderr, "df_profile: tbs=%" PRId64 " insns=%" PRId64
            " ops=%" PRId64 " ns=%" PRId64 " ns_per_tb=%.0f"
            " ns_per_insn=%.1f ns_per_op=%.1f\n",
            df_prof_tbs, df_prof_insns, df_prof_ops, df_prof_ns,
            (double)df_prof_ns / df_prof_tbs,
            (double)df_prof_ns / MAX(df_prof_insns, 1),
            (double)df_prof_ns / MAX(df_prof_ops, 1));
}

static bool df_disabled(void)
{
    if (!df_off_read) {
        const char *e = getenv("QEMU_DF_OFF");

        df_off = e && atoi(e) != 0;
        df_off_read = true;
    }
    return df_off;
}

static bool df_test(const uint64_t *p, unsigned bit);

/*
 * Cross-check output.
 *
 * This extractor is a second implementation of the same derivation the
 * behavioural oracle does, written lean enough to run on every translation.
 * Two implementations of one thing agree until they do not, so it can emit
 * its answer in the oracle's own report format and be diffed against it.
 * QEMU_DF_DUMP names the file; QEMU_DF_PC_LO/_PC_HI bound it.
 */
static FILE *df_dump;
static bool df_dump_read;
static uint64_t df_pc_lo, df_pc_hi = UINT64_MAX;

static FILE *df_dumping(void)
{
    if (!df_dump_read) {
        const char *e = getenv("QEMU_DF_DUMP");
        const char *lo = getenv("QEMU_DF_PC_LO");
        const char *hi = getenv("QEMU_DF_PC_HI");

        df_dump_read = true;
        if (e && *e) {
            df_dump = fopen(e, "w");
            if (df_dump) {
                setvbuf(df_dump, NULL, _IOLBF, 0);
                fprintf(df_dump, "# qemu insn-dataflow\n");
                fprintf(df_dump, "T target=%s env_size=0 nb_tcg_globals=%d\n",
                        TARGET_NAME, tcg_ctx->nb_globals);
                for (unsigned i = 0; i < (unsigned)tcg_ctx->nb_globals; i++) {
                    uint32_t off, size;
                    const char *nm = insn_dataflow_reg_name(i, &off, &size);

                    if (nm) {
                        fprintf(df_dump, "G %6u %2u %s\n", off, size, nm);
                    }
                }
            }
        }
        if (lo) {
            df_pc_lo = strtoull(lo, NULL, 0);
        }
        if (hi) {
            df_pc_hi = strtoull(hi, NULL, 0);
        }
    }
    return df_dump;
}

/*
 * Print one provenance set: register names, @offset for an env field, and
 * L<slot> for the value an access returned.
 *
 * The load-data bits have to be spelled or a load's destination prints
 * `from=-`, which every reader of this dump takes to mean "came from
 * nothing" -- the broken-dependency-chain signal.  A new namespace region
 * that prints as absence would have turned every load into a false zeroing
 * idiom.
 */
static void df_emit_prov(FILE *f, const uint64_t *pv, unsigned nregs)
{
    unsigned k = 0;

    for (unsigned b = 0; b < INSN_DF_MAX_REGS; b++) {
        unsigned slot;
        bool ok;

        if (!df_test(pv, b)) {
            continue;
        }
        if (b < nregs) {
            const char *rn = insn_dataflow_reg_name(b, NULL, NULL);

            fprintf(f, "%s%s", k++ ? "," : "", rn ? rn : "?");
        } else if (b == INSN_DF_ZERO_PROV_BIT) {
            /*
             * The architectural zero register.  Rendered because a dump that
             * cannot show a fact the record carries reads as the record not
             * carrying it -- which is exactly how this line came to be
             * written: the bit was reaching writes[].prov and the dump said
             * `from=x10/a0`, naming one of two sources.
             */
            fprintf(f, "%sZERO", k++ ? "," : "");
        } else if (b == INSN_DF_IMM_PROV_BIT) {
            /*
             * The instruction's own encoded immediate.  Rendered for the
             * reason ZERO is: a dump that cannot show a fact the record
             * carries reads as the record not carrying it.
             */
            fprintf(f, "%sIMM", k++ ? "," : "");
        } else if (insn_dataflow_prov_memop(b, &slot)) {
            fprintf(f, "%sL%u", k++ ? "," : "", slot);
        } else {
            uint32_t foff = insn_dataflow_prov_field(b, &ok);

            if (ok) {
                fprintf(f, "%s@%u", k++ ? "," : "", foff);
            }
        }
    }
    if (!k) {
        fputc('-', f);
    }
}

static void df_emit(uint64_t pc, const InsnDataflow *d)
{
    FILE *f = df_dumping();
    unsigned n = tcg_ctx->nb_globals;

    if (!f || pc < df_pc_lo || pc > df_pc_hi) {
        return;
    }
    for (unsigned i = 0; i < n; i++) {
        uint32_t off, size;
        const char *nm = insn_dataflow_reg_name(i, &off, &size);

        if (!nm) {
            continue;
        }
        if (df_test(d->rd, i)) {
            fprintf(f, "D 0x%" PRIx64 " r reg=%s off=%u size=%u via=arg "
                    "op=df argno=0\n", pc, nm, off, size);
        }
        if (df_test(d->wr, i)) {
            const uint64_t *pv = NULL;

            for (unsigned w = 0; w < d->n_writes; w++) {
                if (d->writes[w].reg == i) {
                    pv = d->writes[w].prov;
                    break;
                }
            }
            fprintf(f, "D 0x%" PRIx64 " w reg=%s off=%u size=%u via=arg "
                    "op=df argno=0 from=", pc, nm, off, size);
            if (pv) {
                df_emit_prov(f, pv, n);
            } else {
                fputc('-', f);
            }
            fputc('\n', f);
        }
        if (df_test(d->kill, i)) {
            fprintf(f, "D 0x%" PRIx64 " k reg=%s off=%u size=%u via=arg "
                    "op=df argno=0\n", pc, nm, off, size);
        }
    }
    for (unsigned i = 0; i < d->n_fields; i++) {
        const InsnDataflowField *fl = &d->fields[i];

        if (fl->dir & INSN_DF_RD) {
            fprintf(f, "D 0x%" PRIx64 " r reg=? off=%u size=%u via=ld op=df "
                    "argno=0\n", pc, fl->off, fl->size);
        }
        if (fl->dir & INSN_DF_WR) {
            fprintf(f, "D 0x%" PRIx64 " w reg=? off=%u size=%u via=st op=df "
                    "argno=0 from=", pc, fl->off, fl->size);
            df_emit_prov(f, fl->prov, n);
            fputc('\n', f);
        }
    }
    /*
     * THE ORDERED LISTS, on a record type of their own.
     *
     * The D lines above are emitted in REGISTER-INDEX order and always were:
     * they answer membership, and a reader that wanted an order would be
     * reading the target's numbering.  An O line is the position the
     * translation stated the member at, which is the fact the D lines cannot
     * carry and the one a list-publishing consumer is built on.  A separate
     * type rather than a field on D because every existing reader of this
     * format skips an unknown line and none of them survives a changed one.
     */
    for (unsigned dir = 0; dir < 2; dir++) {
        const InsnDataflowOrdered *list = dir ? d->wr_ord : d->rd_ord;
        unsigned cnt = dir ? d->n_wr_ord : d->n_rd_ord;
        bool ovf = dir ? d->wr_ord_overflow : d->rd_ord_overflow;

        for (unsigned i = 0; i < cnt; i++) {
            fprintf(f, "O 0x%" PRIx64 " %s pos=%u ", pc, dir ? "w" : "r", i);
            switch (list[i].kind) {
            case INSN_DF_ORD_GLOBAL: {
                const char *nm = insn_dataflow_reg_name(list[i].index,
                                                        NULL, NULL);
                fprintf(f, "global reg=%s\n", nm ? nm : "?");
                break;
            }
            case INSN_DF_ORD_FIELD:
                fprintf(f, "field off=%u size=%u\n",
                        d->fields[list[i].index].off,
                        d->fields[list[i].index].size);
                break;
            case INSN_DF_ORD_DISCARD:
                fprintf(f, "discard reg=%s zero=%u by_index=%u\n",
                        d->discards[list[i].index].reg
                            ? d->discards[list[i].index].reg : "-",
                        d->discards[list[i].index].zero_reg,
                        d->discards[list[i].index].by_index);
                break;
            case INSN_DF_ORD_ZERO:
                fprintf(f, "zeroreg\n");
                break;
            case INSN_DF_ORD_NAME:
                /*
                 * The NAME form prints its register the same way the
                 * GLOBAL form does, and for the same reason: the name IS
                 * the identity.  There is no D line to pair it with --
                 * a register resolved at translation time out of the CPU
                 * OBJECT sets no bit in @rd and has no env range -- so
                 * without this arm the entry printed `unknown kind=4` and
                 * every reader scored a stated source as garbage.  A
                 * checker comparing the ordered list against the D-line
                 * bitmap has to be told this kind is legitimately absent
                 * from that bitmap; ordlist_check.py's `name` arm is the
                 * matching half and says so.
                 */
                fprintf(f, "name reg=%s\n",
                        d->named_reads[list[i].index].reg
                            ? d->named_reads[list[i].index].reg : "?");
                break;
            default:
                fprintf(f, "unknown kind=%u\n", list[i].kind);
                break;
            }
        }
        if (ovf) {
            /*
             * Said even when the list is empty, because an overflow is
             * exactly the state in which the printed list is NOT the answer.
             */
            fprintf(f, "O 0x%" PRIx64 " %s truncated\n", pc, dir ? "w" : "r");
        }
    }
    /*
     * AND THE OTHER THREE REASONS THE LISTS ARE NOT THE ANSWER.
     *
     * plugin_df_list() refuses on FOUR conditions, not one: the list's own
     * overflow, printed above as `truncated`, and the three flags
     * plugin_df_complete() reads -- fields, writes, discards.  The test is
     * spelled out here rather than shared with plugins/api.c because that
     * file is the plugin ABI and this one is the dump; a new flag has to be
     * added to both, and the comment above each says so.  Until this
     * line existed the dump could express only the first, so a reader of
     * this file -- ordlist_check is one, and it is a standing acceptance --
     * saw a complete-looking list of 24 entries for an instruction whose
     * accessors were handing every consumer QEMU_PLUGIN_DF_INCOMPLETE.  A
     * dump that cannot say its subject is refused is the failure mode this
     * whole interface is shaped against, so it says it, and it names WHICH
     * limit so the reading is actionable rather than a bare flag.
     *
     * Printed only when something is set: an X line means "these lists are
     * NOT the answer", and a reader that never sees one has a whole file of
     * answers.
     */
    if (d->fields_overflow || d->writes_overflow || d->discards_overflow) {
        fprintf(f, "X 0x%" PRIx64 " incomplete fields=%u writes=%u"
                " discards=%u\n", pc, d->fields_overflow,
                d->writes_overflow, d->discards_overflow);
    }
    for (unsigned i = 0; i < d->n_mem_rd; i++) {
        fprintf(f, "D 0x%" PRIx64 " r mem op=df\n", pc);
    }
    for (unsigned i = 0; i < d->n_mem_wr; i++) {
        fprintf(f, "D 0x%" PRIx64 " w mem op=df\n", pc);
    }
    /*
     * CP-M: the accesses as the emitters stated them.  A separate record
     * type rather than more of the D lines above, because what it carries is
     * the thing those lines cannot say -- which registers computed the
     * ADDRESS, and separately which produced the DATA.
     */
    for (unsigned i = 0; i < d->n_memops; i++) {
        const InsnDataflowMemop *mo = &d->memops[i];

        fprintf(f, "M 0x%" PRIx64 " %s slot=%u size=%u addr=", pc,
                mo->is_store ? "st" : "ld", i, mo->size);
        df_emit_prov(f, mo->addr_prov, n);
        fputs(" data=", f);
        if (mo->is_store) {
            df_emit_prov(f, mo->data_prov, n);
        } else {
            fprintf(f, "L%u", i);
        }
        fputc('\n', f);
    }
    if (d->memops_overflow || d->memops_unnoted) {
        fprintf(f, "M 0x%" PRIx64 " incomplete overflow=%u unnoted=%u\n",
                pc, d->memops_overflow, d->memops_unnoted);
    }
    fprintf(f, "A 0x%" PRIx64 " ops=0 calls=%u opaque=%u\n",
            pc, d->n_calls, d->n_calls);
    /*
     * CP-H's verdict gets a record type of its own rather than three more
     * fields on the A line.  This dump is written in the behavioural oracle's
     * report format precisely so the two can be diffed against each other, and
     * a line that carries fields the oracle's own A line cannot differs on
     * every instruction -- which would make a whole-file diff useless for the
     * thing it exists for.  An unknown line type is skipped by every reader of
     * this format; a changed one is not.
     */
    if (d->n_calls) {
        fprintf(f, "H 0x%" PRIx64 " model=%u unknown=%u unbounded=%u\n",
                pc, d->helper_model, d->n_helper_unknown,
                d->n_helper_unbounded);
    }
    /*
     * The representation-carrier folds, on a record type of its own for the
     * reason the H line has one: this dump is diffed against the behavioural
     * oracle's report and a line carrying a field the oracle cannot produce
     * would differ on every instruction.  Printed only when the rule fired, so
     * its presence in a dump is the firing witness and its absence over a
     * whole range is a measurement rather than a silence.
     */
    if (d->n_repr_carrier) {
        fprintf(f, "R 0x%" PRIx64 " repr_carrier folds=%u\n",
                pc, d->n_repr_carrier);
    }
}

static bool df_profiling(void)
{
    if (!df_prof_read) {
        const char *e = getenv("QEMU_DF_PROFILE");

        df_prof = e && atoi(e) != 0;
        df_prof_read = true;
        if (df_prof) {
            const char *n = getenv("QEMU_DF_PROFILE_EVERY");

            if (n) {
                df_prof_every = strtoll(n, NULL, 0);
            }
        }
    }
    return df_prof;
}

static void df_touch(size_t i)
{
    if (df_stamp[i] != df_gen) {
        df_stamp[i] = df_gen;
        memset(df_prov[i], 0, sizeof(df_prov[i]));
        df_envoff[i] = INSN_DF_NOT_ENV;
        df_defop[i] = NULL;
    }
}

static uint64_t *df_prov_of(size_t i)
{
    df_touch(i);
    return df_prov[i];
}

static int64_t df_envoff_of(size_t i)
{
    df_touch(i);
    return df_envoff[i];
}

static void df_set_envoff(size_t i, int64_t v)
{
    df_touch(i);
    df_envoff[i] = v;
}

static const TCGOp *df_defop_of(size_t i)
{
    df_touch(i);
    return df_defop[i];
}

static void df_set_defop(size_t i, const TCGOp *op)
{
    df_touch(i);
    df_defop[i] = op;
}

static void df_or(uint64_t *dst, const uint64_t *src)
{
    for (int i = 0; i < INSN_DF_REG_WORDS; i++) {
        dst[i] |= src[i];
    }
}

static void df_bit(uint64_t *p, unsigned bit)
{
    if (bit < INSN_DF_MAX_REGS) {
        p[bit / 64] |= 1ULL << (bit % 64);
    }
}

static bool df_test(const uint64_t *p, unsigned bit)
{
    return bit < INSN_DF_MAX_REGS && (p[bit / 64] & (1ULL << (bit % 64)));
}

/*
 * The load-data bits, as a mask over the top provenance word.
 *
 * They are the top INSN_DF_MAX_MEMOPS bits of the namespace so that the
 * whole region lives in one word and clearing it costs one AND -- which
 * matters because it is cleared once per instruction, see
 * df_settle_memop_prov().
 */
QEMU_BUILD_BUG_ON(INSN_DF_MEMOP_PROV_BASE / 64 != INSN_DF_REG_WORDS - 1);
#define DF_MEMOP_WORD  (INSN_DF_REG_WORDS - 1)
#define DF_MEMOP_MASK  (~0ULL << (INSN_DF_MEMOP_PROV_BASE % 64))

/*
 * Is @ts a guest register?
 *
 * Globals occupy the first nb_globals slots of the temps array, so a global's
 * index in that array is its register number -- no lookup table, and nothing
 * to keep in step with the target's own.
 */
static bool df_reg(const TCGTemp *ts, unsigned *idx)
{
    TCGContext *s = tcg_ctx;
    size_t i;

    if (ts->kind != TEMP_GLOBAL) {
        return false;
    }
    i = ts - s->temps;
    if (i >= (size_t)s->nb_globals) {
        return false;
    }
    *idx = (unsigned)i;
    return true;
}

/* Direct env access: a load or a store of how many bytes? */
static bool df_ldst(const TCGOp *op, bool *store, uint32_t *size)
{
    switch (op->opc) {
    case INDEX_op_ld8u_i32: case INDEX_op_ld8s_i32:
    case INDEX_op_ld8u_i64: case INDEX_op_ld8s_i64:
        *store = false; *size = 1; return true;
    case INDEX_op_ld16u_i32: case INDEX_op_ld16s_i32:
    case INDEX_op_ld16u_i64: case INDEX_op_ld16s_i64:
        *store = false; *size = 2; return true;
    case INDEX_op_ld_i32:
    case INDEX_op_ld32u_i64: case INDEX_op_ld32s_i64:
        *store = false; *size = 4; return true;
    case INDEX_op_ld_i64:
        *store = false; *size = 8; return true;
    case INDEX_op_ld_vec:
        *store = false; *size = tcg_type_size(TCGOP_TYPE(op)); return true;
    /*
     * The DUPLICATING vector load.  It has the same three-argument shape as
     * ld_vec -- destination, base pointer, byte offset -- and reads ONE
     * ELEMENT rather than a whole vector: tcg_gen_dup_mem_vec() takes the
     * element width in the op's vece field and broadcasts it.  Reading the
     * size from TCGOP_TYPE() here would name the whole destination vector as
     * the source range, which is a different register on a target whose
     * vector file is declared per element.
     *
     * Missing it entirely is what this case fixes.  x86_64's `vpbroadcastb
     * %xmm0, %ymm0` lowers to exactly one of these plus the stores that
     * spread it, and with the op unclassified the walk saw the stores and no
     * read at all -- the destination came back with an EMPTY provenance and
     * QEMU stated that the instruction reads nothing.
     */
    case INDEX_op_dupm_vec:
        *store = false; *size = 1u << TCGOP_VECE(op); return true;
    case INDEX_op_st8_i32: case INDEX_op_st8_i64:
        *store = true; *size = 1; return true;
    case INDEX_op_st16_i32: case INDEX_op_st16_i64:
        *store = true; *size = 2; return true;
    case INDEX_op_st_i32: case INDEX_op_st32_i64:
        *store = true; *size = 4; return true;
    case INDEX_op_st_i64:
        *store = true; *size = 8; return true;
    case INDEX_op_st_vec:
        *store = true; *size = tcg_type_size(TCGOP_TYPE(op)); return true;
    default:
        return false;
    }
}

/*
 * Append one member to an ORDERED list, at the position of its first
 * observation.
 *
 * Idempotent by (kind, index), because the caller sites are the places the
 * facts are STATED and a fact stated twice is one fact: an operand read by
 * two ops of the same instruction, a register written by both arms of a
 * lowering.  Keeping the FIRST position is what makes the order a property of
 * the encoding rather than of how many times the target happened to touch a
 * temp.
 *
 * A full list is FLAGGED and the member is dropped, on the rule the rest of
 * this file runs under: a list short by a member is a missing dependency, and
 * the flag is what stops a consumer reading the short list as a whole one.
 * The flag is not "this instruction is wide" -- it is "do not publish this
 * list at all".
 */
static void df_ord_add(InsnDataflowOrdered *list, uint8_t *n, uint8_t *ovf,
                       uint8_t kind, unsigned index)
{
    /*
     * An index that does not fit the byte is not recordable, and recording a
     * TRUNCATED one would name a different register.  The bounds it can come
     * from -- INSN_DF_MAX_REGS, INSN_DF_MAX_FIELDS, INSN_DF_MAX_DISCARDS --
     * are all below 256 today; the check is here so that a target that raises
     * one fails loudly rather than silently renaming an operand.
     */
    if (index > 0xff) {
        *ovf = 1;
        return;
    }
    for (unsigned i = 0; i < *n; i++) {
        if (list[i].kind == kind && list[i].index == (uint8_t)index) {
            return;
        }
    }
    if (*n >= INSN_DF_MAX_ORDERED) {
        *ovf = 1;
        return;
    }
    list[*n].kind = kind;
    list[*n].index = (uint8_t)index;
    (*n)++;
}

static void df_ord_read(InsnDataflow *d, uint8_t kind, unsigned index)
{
    df_ord_add(d->rd_ord, &d->n_rd_ord, &d->rd_ord_overflow, kind, index);
}

static void df_ord_write(InsnDataflow *d, uint8_t kind, unsigned index)
{
    df_ord_add(d->wr_ord, &d->n_wr_ord, &d->wr_ord_overflow, kind, index);
}

/*
 * A source stated by NAME alone -- see INSN_DF_MAX_NAMED_READS.
 *
 * Idempotent by name, on the same rule df_ord_add() runs under: an
 * instruction that states the same register twice states one fact.  A full
 * array is FLAGGED and the member dropped, and the flag lands on the READ
 * list's overflow because that is the list a consumer would otherwise read
 * short.
 */
static void df_add_named_read(InsnDataflow *d, const char *reg)
{
    unsigned i;

    for (i = 0; i < d->n_named_reads; i++) {
        if (strcmp(d->named_reads[i].reg, reg) == 0) {
            df_ord_read(d, INSN_DF_ORD_NAME, i);
            return;
        }
    }
    if (d->n_named_reads >= INSN_DF_MAX_NAMED_READS) {
        d->named_reads_overflow = 1;
        d->rd_ord_overflow = 1;
        return;
    }
    d->named_reads[d->n_named_reads].reg = reg;
    df_ord_read(d, INSN_DF_ORD_NAME, d->n_named_reads);
    d->n_named_reads++;
}

/*
 * A CPUArchState byte range enters whichever list(s) its direction names.
 *
 * Both, when the emitter stated both -- a gvec helper's in-place destination
 * is read and written by one row, and a consumer that saw it in only one list
 * would either miss the input edge or miss the output.
 */
static void df_ord_field(InsnDataflow *d, unsigned field, uint8_t dir)
{
    if (dir & INSN_DF_RD) {
        df_ord_read(d, INSN_DF_ORD_FIELD, field);
    }
    if (dir & INSN_DF_WR) {
        df_ord_write(d, INSN_DF_ORD_FIELD, field);
    }
}

/*
 * THE VALUE THIS INSTRUCTION ALREADY PUT IN @reg, or NULL if it has not
 * written it yet.
 *
 * A lowering that computes IN PLACE reads the destination global back after
 * writing it -- riscv64's `flw fa0,0(a6)` loads straight into cpu_fpr[rd]
 * and then NaN-boxes it with `ori cpu_fpr[rd],cpu_fpr[rd],mask`, mipsel's
 * `lwc1` does the same, and aarch64's post-indexed loads write the base
 * register and read it again to form the writeback.  Read as an operand
 * fetch, that second read says the instruction depends on the architectural
 * incoming value of a register whose incoming value the instruction had
 * already destroyed.
 *
 * It does not.  The value in the global at that point is the one THIS
 * instruction produced, so the dependency the read carries is the
 * dependency of that production -- which is exactly what a renaming regfile
 * would forward (R7: "would the regfile have to respect this edge for the
 * instruction to execute correctly?").  Returning the earlier write's
 * provenance and substituting it for the register's own bit is that
 * forwarding, done once, in the walk that has the fact.
 *
 * It cannot LOSE an edge.  If the earlier write was itself partial -- a
 * `deposit` whose background operand was the same global -- then R is in
 * its own provenance already and the forwarded set still carries it; the
 * substitution only removes R where R's value at the point of the read owed
 * nothing to R's value at the start of the instruction.
 */
static const uint64_t *df_written_prov(const InsnDataflow *d, unsigned reg)
{
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == reg) {
            return d->writes[i].prov;
        }
    }
    return NULL;
}

static void df_add_write(InsnDataflow *d, unsigned reg, const uint64_t *prov,
                         bool supplies_value)
{
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == reg) {
            /*
             * STICKY, and the OR is the point.  A register written twice --
             * once by a lowering that only re-expressed it and once by an
             * emitter that put a new value in -- has had a value put in it,
             * and the union of the two provenances cannot say so.  x86's
             * `clc` is exactly that pair.
             */
            d->writes[i].supplies_value |= supplies_value;
            df_or(d->writes[i].prov, prov);
            return;
        }
    }
    if (d->n_writes >= INSN_DF_MAX_WRITES) {
        d->writes_overflow = 1;
        return;
    }
    d->writes[d->n_writes].reg = (uint8_t)reg;
    d->writes[d->n_writes].supplies_value = supplies_value;
    memcpy(d->writes[d->n_writes].prov, prov, sizeof(d->writes[0].prov));
    d->n_writes++;
}

/*
 * Record an access to an env byte range, and for a write, where its value came
 * from.
 *
 * Which way this code should err, stated once here because every choice below
 * follows it:
 *
 *   A dependency recorded that does not exist is PESSIMISTIC.  A consumer
 *   serialises two instructions that could have run together and loses some
 *   scheduling accuracy.  Nothing it computes is wrong.
 *
 *   A dependency MISSED is WRONG.  A consumer reorders across an edge the
 *   machine could not have crossed, and everything downstream of that is
 *   unsound.
 *
 * They are not symmetric and this code does not treat them as though they
 * were.  Where it cannot tell, it records the dependency.  The concrete case
 * that made this worth writing down: giving a field write an empty provenance
 * because field *reads* were not tracked would have reported psubb
 * %xmm2,%xmm2 as breaking its dependency chain, which it does not -- a missed
 * dependency, arrived at by a change that looked like a simplification.
 */
/*
 * CP-M, THE ENV-SCRATCH HALF (#218/#246).
 *
 * A target may route a value through a byte range of CPUArchState that names
 * no architectural register.  x86's `movdqu (%rax),%xmm4` is the shape:
 * QEMU stores the loaded halves into env->xmm_t0 and then copies xmm_t0 into
 * the destination, so the destination's provenance reads `@2912` -- a
 * translation scratch -- where the machine's answer is the LOAD.  The same
 * lowering carries `pmovmskb`, `pslldq`, `psrldq` and their VEX forms.
 *
 * The value did not come from nowhere and it did not come from a register:
 * this instruction PUT it there, and the write that put it there is already
 * in @d->fields with its own provenance.  Forwarding that provenance is
 * QEMU's own statement of the same instruction, read one step further back --
 * the identical move the folded-register note makes for a constant.
 *
 * THE FORWARD IS CONFINED TO RANGES NOTHING NAMES, in both directions, so it
 * can never cost a name (R12.1):
 *
 *   - a READ of a range some target DECLARED keeps the field bit it always
 *     had; the register is the answer and there is nothing better to say;
 *   - a WRITE that overlaps and IS named is not folded away either -- the
 *     whole forward is refused for that read, and the field bit stands;
 *   - a read only PARTLY covered by this instruction's writes keeps the field
 *     bit too, because the uncovered bytes are the architectural prior value
 *     and dropping them would publish a SHORT set.
 *
 * Bounded to the instruction being walked: @d is the per-instruction
 * descriptor and its field list starts empty, so nothing here can see a write
 * from the instruction before.
 */
static bool df_field_named(uint32_t off, uint32_t size)
{
    char nm[64];

    return insn_dataflow_field_reg(off, size, nm, sizeof(nm));
}

static bool df_field_forward(const InsnDataflow *d, uint32_t off, uint32_t size,
                             uint64_t *out)
{
    uint64_t need, have = 0;

    if (size == 0 || size > 64 || df_field_named(off, size)) {
        return false;
    }
    need = size == 64 ? ~(uint64_t)0 : (((uint64_t)1 << size) - 1);
    memset(out, 0, sizeof(uint64_t) * INSN_DF_REG_WORDS);
    for (unsigned i = 0; i < d->n_fields; i++) {
        const InsnDataflowField *f = &d->fields[i];
        uint32_t lo, hi;

        if (!(f->dir & INSN_DF_WR)) {
            continue;
        }
        if (f->off + f->size <= off || f->off >= off + size) {
            continue;
        }
        if (df_field_named(f->off, f->size)) {
            return false;
        }
        lo = MAX(f->off, off);
        hi = MIN(f->off + f->size, off + size);
        have |= (hi - lo == 64 ? ~(uint64_t)0
                               : ((((uint64_t)1 << (hi - lo)) - 1) << (lo - off)));
        df_or(out, f->prov);
    }
    return have == need;
}

static void df_add_field(InsnDataflow *d, uint32_t off, uint32_t size,
                         uint8_t dir, const uint64_t *prov)
{
    for (unsigned i = 0; i < d->n_fields; i++) {
        if (d->fields[i].off == off && d->fields[i].size == size) {
            d->fields[i].dir |= dir;
            if (prov) {
                df_or(d->fields[i].prov, prov);
            }
            /*
             * THE ORDER IS PER DIRECTION, which is why this is here and not
             * only on the append below.  A field first touched as a READ and
             * written later is one row in fields[] with two directions, and
             * its position in the WRITE list is where the write was stated,
             * not where the read was.  Merging the row does not merge the
             * two positions.
             */
            df_ord_field(d, i, dir);
            return;
        }
    }
    if (d->n_fields >= INSN_DF_MAX_FIELDS) {
        /*
         * Out of room to say what was touched.  The instruction's field
         * accesses are now under-reported, which for a write means a
         * dependency could go missing, so it is flagged rather than dropped
         * quietly.
         */
        d->fields_overflow = 1;
        return;
    }
    d->fields[d->n_fields].off = off;
    d->fields[d->n_fields].size = (uint16_t)size;
    d->fields[d->n_fields].dir = dir;
    memset(d->fields[d->n_fields].prov, 0,
           sizeof(d->fields[d->n_fields].prov));
    if (prov) {
        memcpy(d->fields[d->n_fields].prov, prov,
               sizeof(d->fields[d->n_fields].prov));
    }
    df_ord_field(d, d->n_fields, dir);
    d->n_fields++;
}

/*
 * Record a destination the encoding names that the emulator threw away.
 *
 * The provenance is @ts's at the end of the instruction, and there are two
 * ways to read that, matching the two things @ts can be.  A GLOBAL is a guest
 * register: if this instruction wrote it, the discarded value came from
 * wherever that write came from; if it only read it, the discarded value IS
 * that register.  Anything else is a temp, and the walk has already computed
 * its provenance in place.
 *
 * Merged on the register NAME rather than appended, so an emitter that states
 * the same discarded destination twice -- once per lowering arm -- produces
 * one row whose provenance is the union, exactly as a register written twice
 * does in df_add_write().
 */
static void df_add_discard(InsnDataflow *d, const DfDiscardNote *n)
{
    const char *reg = n->reg;
    bool zero = n->zero;
    const TCGTemp *ts = n->ts;
    uint64_t prov[INSN_DF_REG_WORDS];
    unsigned idx;

    if ((reg == NULL && !zero) || ts == NULL) {
        return;
    }
    if (n->holder) {
        /*
         * A holder that no op but the accessor's own movi ever wrote was a
         * SOURCE use of the register, not a destination.  `mov x0,xzr`
         * reaches the same accessor as `cmp x0,x1` and publishing a write
         * for it would fabricate a destination -- the error direction this
         * whole file treats as worse than a missing one, because it is a
         * dependency that does not exist.
         */
        if (df_reg(ts, &idx) ||
            df_defop_of(ts - tcg_ctx->temps) == n->anchor) {
            return;
        }
    }
    memset(prov, 0, sizeof(prov));
    if (df_reg(ts, &idx)) {
        const uint64_t *fwd = df_written_prov(d, idx);

        if (fwd) {
            df_or(prov, fwd);
        } else {
            df_bit(prov, idx);
        }
    } else {
        df_or(prov, df_prov_of(ts - tcg_ctx->temps));
    }

    for (unsigned i = 0; i < d->n_discards; i++) {
        bool same = zero ? (d->discards[i].zero_reg != 0)
                         : (d->discards[i].reg != NULL &&
                            !strcmp(d->discards[i].reg, reg));

        if (same) {
            df_or(d->discards[i].prov, prov);
            /*
             * STICKY, and in one direction only: a register stated twice,
             * once by a lowering arm that threw the write away and once by
             * one that performed it, HAS been performed.  The opposite
             * accumulation would let a discarding arm erase the fact that
             * the machine's write happened.
             */
            d->discards[i].by_index |= n->by_index ? 1 : 0;
            df_ord_write(d, INSN_DF_ORD_DISCARD, i);
            return;
        }
    }
    if (d->n_discards >= INSN_DF_MAX_DISCARDS) {
        d->discards_overflow = 1;
        return;
    }
    d->discards[d->n_discards].reg = reg;
    d->discards[d->n_discards].zero_reg = zero ? 1 : 0;
    d->discards[d->n_discards].by_index = n->by_index ? 1 : 0;
    memcpy(d->discards[d->n_discards].prov, prov,
           sizeof(d->discards[d->n_discards].prov));
    df_ord_write(d, INSN_DF_ORD_DISCARD, d->n_discards);
    d->n_discards++;
}

void insn_dataflow_note_reset(void)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    df_n_gvec = 0;
    df_gvec_overflow = false;
    df_n_memop = 0;
    df_memop_overflow = false;
    df_alt_open = false;
    df_alt_mark = 0;
    df_alt_taken = 0;
    df_n_alias = 0;
    df_alias_overflow = false;
    df_n_zero = 0;
    df_zero_overflow = false;
    df_n_discard = 0;
    df_discard_overflow = false;
    df_n_preserve = 0;
    df_preserve_overflow = false;
    df_n_value = 0;
    df_value_overflow = false;
    df_n_carrier = 0;
    df_n_fold = 0;
    df_fold_overflow = false;
    df_n_encread = 0;
    df_encread_overflow = false;
    df_n_imm = 0;
    df_imm_overflow = false;
    df_n_helper = 0;
    df_helper_overflow = false;
}

static const DfHelperNote *df_find_helper(const TCGOp *op);
static bool df_helper_usage_of(const char *name, unsigned argno, uint8_t *dir);
static const DfHelperUsage *df_helper_usage_row(const char *name);
static uint32_t df_helper_argsize(const DfHelperUsage *u, unsigned argno);

/*
 * CP-H census -- which helpers were reached, and WHY each one is not
 * exactly described.
 *
 * The per-helper usage table is a written-down static fact, and which rows
 * belong in it is a MEASUREMENT: the helpers a workload reaches, not the ones
 * that come to mind.  The aggregate counters on InsnDataflow say how many
 * calls were unbounded; they cannot say which helper, which argument, or
 * which of the four reasons.  This says all four, so a row can be written
 * against an observed call rather than against a table row.
 *
 * Translation-time only, behind an env var, and off by default.
 */
#define DF_CENSUS_MAX       1024

/* Why a call was not exactly described.  A call can carry several. */
#define DF_CR_NO_RWG        (1u << 0)   /* !TCG_CALL_NO_READ_GLOBALS */
#define DF_CR_ENV           (1u << 1)   /* handed tcg_env itself */
#define DF_CR_PTR           (1u << 2)   /* pointer that is not env+const */
#define DF_CR_GVEC_MISMATCH (1u << 3)   /* gvec operand k != argument k */
#define DF_CR_ARGS_OVERFLOW (1u << 4)   /* more logical args than we carry */
/*
 * May WRITE every global.  Read exactly as tcg_liveness_analysis() reads it:
 * neither flag set is la_global_kill (every global written), NO_WG alone is
 * la_global_sync (every global read, none written), NO_RWG is neither.  So
 * "may write" is the absence of BOTH flags, not the absence of NO_WG -- a
 * helper declared TCG_CALL_NO_RWG carries 0x1 and no 0x2, and testing 0x2
 * alone would call it a global writer.
 */
#define DF_CR_NO_WRG        (1u << 5)

typedef struct DfHelperCensus {
    const char *name;
    uint32_t flags;
    uint8_t  nargs;
    uint32_t reasons;           /* union of DF_CR_* over every call seen */
    uint32_t ptr_args;          /* logical args that arrived as pointers */
    uint32_t env_args;          /* logical args that were tcg_env */
    uint32_t unknown_args;      /* pointer args with no direction written */
    uint32_t stated_args;       /* pointer args a direction WAS stated for */
    uint64_t calls;
    uint64_t unknown_pairs;
} DfHelperCensus;

static DfHelperCensus df_census[DF_CENSUS_MAX];
static unsigned df_n_census;
static bool df_census_overflow;
static QemuMutex df_census_lock;
static bool df_census_on, df_census_read;
static const char *df_census_path;

static void df_census_dump_locked(void);

static bool df_censusing(void)
{
    if (!df_census_read) {
        const char *e = getenv("QEMU_DF_HELPER_CENSUS");

        df_census_read = true;
        if (e && *e) {
            df_census_path = e;
            df_census_on = true;
            qemu_mutex_init(&df_census_lock);
        }
    }
    return df_census_on;
}

/*
 * Keyed on the NAME POINTER.  TCGHelperInfo::name is a string literal in the
 * generated helper tables, so one helper is one pointer; comparing the
 * pointer rather than the bytes keeps this off the translation hot path even
 * when it is switched on.  A duplicate row would be visible in the dump as
 * two rows with the same name, which is the failure this would produce and
 * it has not been observed.
 */
static DfHelperCensus *df_census_row(const char *name, uint32_t flags,
                                     uint8_t nargs)
{
    for (unsigned i = 0; i < df_n_census; i++) {
        if (df_census[i].name == name) {
            return &df_census[i];
        }
    }
    if (df_n_census >= DF_CENSUS_MAX) {
        df_census_overflow = true;
        return NULL;
    }
    df_census[df_n_census].name = name;
    df_census[df_n_census].flags = flags;
    df_census[df_n_census].nargs = nargs;
    return &df_census[df_n_census++];
}

/* Caller holds df_census_lock. */
static void df_census_dump_locked(void)
{
    FILE *f;

    if (!df_census_on || !df_census_path) {
        return;
    }
    f = fopen(df_census_path, "w");
    if (!f) {
        return;
    }
    fprintf(f, "# qemu insn-dataflow CP-H helper census\n");
    fprintf(f, "# target=%s\n", TARGET_NAME);
    fprintf(f, "# overflow=%d rows=%u\n", (int)df_census_overflow, df_n_census);
    fprintf(f, "# name\tcalls\tnargs\tflags\treasons\tptr_args\tenv_args\t"
               "unknown_args\tstated_args\tunknown_pairs\n");
    for (unsigned i = 0; i < df_n_census; i++) {
        const DfHelperCensus *c = &df_census[i];

        fprintf(f, "%s\t%" PRIu64 "\t%u\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t"
                "%" PRIu64 "\n",
                c->name, c->calls, c->nargs, c->flags, c->reasons,
                c->ptr_args, c->env_args, c->unknown_args, c->stated_args,
                c->unknown_pairs);
    }
    fclose(f);
}

/* Fold @n consecutive temps' provenance -- and their own bits -- into @dst. */
static void df_prov_add_temps(uint64_t *dst, const void *tsv, unsigned n)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *ts = (TCGTemp *)(uintptr_t)tsv;

    for (unsigned i = 0; i < n; i++) {
        size_t ti = (size_t)((ts + i) - s->temps);
        unsigned idx;

        /*
         * These pointers came from an emitter rather than from the op
         * stream, so they are bounds-checked here and nowhere else.  A temp
         * outside the array would otherwise read whatever follows it and
         * call the result a dependency.
         */
        if (ti >= TCG_MAX_TEMPS) {
            continue;
        }
        df_or(dst, df_prov_of(ti));
        if (df_reg(ts + i, &idx)) {
            df_bit(dst, idx);
        }
    }
}

/*
 * Is any of the @n consecutive temps at @tsv one the emitter named as the
 * architectural zero register, among the notes in [@lo, @hi)?
 *
 * The two callers want two different windows and both are half-open ranges
 * over the same append-ordered list.
 *
 * THE MEMOP PATH passes [0, note->zero_n): the count taken when the access's
 * own note was recorded, so a zero-register operand read by a LATER
 * instruction cannot name this store's data -- the same discipline the
 * address aliases use, for the same reason.  It does not need the lower bound
 * because a store's data temp cannot be the shared constant for any reason
 * other than its data operand having been the zero register.
 *
 * THE WRITE PATH passes the window of notes taken INSIDE the instruction
 * being walked, and needs the lower bound for the reason DfZeroNote's comment
 * gives: a write is not a store, an ordinary op reaches a constant zero for
 * reasons of its own, and a prefix window would let one instruction's zero
 * register reach every write after it.
 */
static bool df_zero_reg_temp(const void *tsv, unsigned n,
                             unsigned lo, unsigned hi)
{
    const TCGTemp *ts = (const TCGTemp *)tsv;

    if (hi > df_n_zero) {
        hi = df_n_zero;
    }
    for (unsigned i = 0; i < n; i++) {
        for (unsigned k = lo; k < hi; k++) {
            if (df_zero[k].ts == (const void *)(ts + i)) {
                return true;
            }
        }
    }
    return false;
}

/*
 * Is the temp at @tsv one a DECODER named as this instruction's encoded
 * immediate, among the notes in [@lo, @hi)?
 *
 * One window only, and it is always the instruction's own -- unlike the
 * zero-register notes there is no memop-prefix caller.  A store's data temp
 * being the shared constant proves the operand was the zero register,
 * because nothing else resolves to it; it proves nothing about an immediate,
 * because a stored immediate and a shift count QEMU invented are the same
 * interned temp.  So this is consulted from the op walk alone, inside the
 * instruction whose emitter spoke.
 */
static bool df_imm_temp(const void *tsv, unsigned lo, unsigned hi)
{
    if (hi > df_n_imm) {
        hi = df_n_imm;
    }
    for (unsigned k = lo; k < hi; k++) {
        /*
         * A VALUE-form note has no temp, and NULL is a temp pointer nobody
         * passes -- but the test is written on ts rather than on the role so
         * that a future note shape cannot accidentally match here.
         */
        if (df_imm[k].ts != NULL && df_imm[k].ts == tsv) {
            return true;
        }
    }
    return false;
}

/*
 * Does an OPERAND-role value note anchor to @op?
 *
 * The scan starts at the block cursor, which is where it must: at the point
 * @op is being walked the cursor has already moved past every note anchored
 * at an EARLIER op (the advance at the top of the op loop), so the notes
 * anchored at @op -- taken by the emitter immediately after it emitted @op
 * -- are the contiguous run beginning there.  Nothing before the cursor can
 * match, and the loop stops at the first note with a different anchor, so
 * this is a constant number of comparisons per op rather than a scan.
 */
static bool df_imm_operand_at(const TCGOp *op, unsigned cursor)
{
    for (unsigned k = cursor; k < df_n_imm; k++) {
        if (df_imm[k].anchor != op) {
            return false;
        }
        if (df_imm[k].ts == NULL &&
            df_imm[k].role == INSN_DF_IMM_ROLE_OPERAND) {
            return true;
        }
    }
    return false;
}

/*
 * Fold the sources of any folded-register operand among the @n consecutive
 * temps at @tsv into @dst, searching the first @scope notes newest-first.
 *
 * @scope is the count taken when the access's own note was recorded, for the
 * reason df_zero_reg_temp() gives: a constant an emitter resolves for a LATER
 * instruction must not retro-name this access's operands.
 *
 * The named source goes through df_prov_add_temps() rather than being turned
 * into a bit here, so a global contributes its register bit and a temp
 * contributes whatever it already carries -- the fact is stated once, in the
 * one namespace, and the folded operand is indistinguishable on the wire from
 * the same operand read live under CF_PCREL.  That is the point.
 */
/*
 * The GLOBAL a fold note names for @ts, or NULL.
 *
 * SAME ACCEPTANCE TEST as df_fold_add_srcs() below -- a note applies only
 * while the op that defined the temp when the note was taken is still the op
 * that defines it here, and a constant (anchor NULL) no op defines cannot go
 * stale.  That test is what keeps x86's A0, which carries every address in a
 * block, from leaking one instruction's folded register into the next.
 *
 * BUT NOT THE SAME SEARCH.  df_fold_add_srcs() runs under a note-count scope
 * captured when the memop note was taken, so "the newest note for this temp"
 * is already the note belonging to the access being resolved, and stopping
 * there is right.  This arm has no such scope: it is called from the op walk
 * with the whole translation's notes in view, so "newest for this temp" is
 * the LAST instruction in the block that folded into A0, and for every
 * earlier one the anchor test would reject and the read the encoding named
 * would be lost -- 245 x86_64 source entries on the w19 corpus, every
 * RIP-relative shape in a block containing more than one.
 *
 * So the search runs on until it finds the note whose anchor IS the temp's
 * current defining op.  That is not weaker: (ts, anchor) identifies exactly
 * the note taken when this op wrote this temp, ops are unique within a
 * translation, and a note taken later in the block is anchored to a later op
 * that cannot be the current one.  Rejection and search-on give the same
 * answer whenever the newest note matches; they differ only where the newest
 * note describes a LATER definition, and there the older matching note is the
 * one the temp is actually holding.
 *
 * Split out because the READ arm needs the register and not a provenance
 * bitmap: a folded operand an op really reads is a SOURCE of the instruction,
 * which is a different fact from where a value came from, and putting it in a
 * provenance instead would decide the consumer's dependency question here.
 */
static const TCGTemp *df_fold_src_of(const TCGTemp *ts, unsigned scope)
{
    size_t ti = (size_t)(ts - tcg_ctx->temps);
    const TCGOp *defop;

    if (ti >= TCG_MAX_TEMPS) {
        return NULL;
    }
    defop = df_defop_of(ti);
    for (unsigned k = scope > df_n_fold ? df_n_fold : scope; k-- > 0; ) {
        if (df_fold[k].ts != (const void *)ts) {
            continue;
        }
        if (df_fold[k].anchor == NULL || df_fold[k].anchor == defop) {
            return (const TCGTemp *)df_fold[k].src_ts;
        }
    }
    return NULL;
}

static void df_fold_add_srcs(uint64_t *dst, const void *tsv, unsigned n,
                             unsigned scope)
{
    const TCGTemp *ts = (const TCGTemp *)tsv;

    for (unsigned i = 0; i < n; i++) {
        size_t ti = (size_t)((ts + i) - tcg_ctx->temps);

        if (ti >= TCG_MAX_TEMPS) {
            continue;
        }
        for (unsigned k = scope > df_n_fold ? df_n_fold : scope; k-- > 0; ) {
            if (df_fold[k].ts != (const void *)(ts + i)) {
                continue;
            }
            /*
             * The newest note for this temp, and the only one that can still
             * be true of it: an older note describes contents a later one
             * replaced.  It applies only if the temp still holds what the
             * note described -- either because nothing can rewrite it (a
             * constant, anchor NULL) or because the op that defined it when
             * the note was taken is still the op that defined it here.
             *
             * Rejecting rather than searching on is deliberate.  A temp
             * redefined since the note is a temp the note is silent about,
             * and reaching further back would answer with a fact about
             * contents that are gone -- x86's A0 carries every address in a
             * block, so that is not a corner case but the common one.
             */
            if (df_fold[k].anchor == NULL ||
                df_fold[k].anchor == df_defop_of(ti)) {
                df_prov_add_temps(dst, df_fold[k].src_ts, 1);
            }
            break;
        }
    }
}

/*
 * Attribute one qemu_ld/qemu_st op to the note its emitter left, and for a
 * load return the provenance bit that stands for the value it returned.
 *
 * Matching is by ORDER within the anchor ranges rather than by op identity,
 * because one note can cover more than one op: a 128-bit access a host
 * cannot perform atomically is emitted as two 64-bit ones by the same
 * emitter, under one note that states the real width.  The note's anchor is
 * the last op that existed when that emitter returned, so every memop op up
 * to and including the anchor belongs to it, and @cursor walks the notes in
 * step with the op walk.
 *
 * An op with no note is recorded as such rather than guessed at.  It would
 * mean a path reached gen_ldst() without passing an emitter that states its
 * operands, and from that point on the notes and the ops are out of step --
 * so the alternative to saying so is attributing one access's address
 * registers to a different access, which is a fabricated dependency wearing
 * the shape of a real one.
 */
static int df_memop_apply(InsnDataflow *d, bool store, unsigned *cursor)
{
    DfMemopNote *n;
    InsnDataflowMemop *m;

    if (*cursor >= df_n_memop) {
        d->memops_unnoted = 1;
        return -1;
    }
    n = &df_memop[*cursor];
    if (n->is_store != store || n->rec >= (int)d->n_memops ||
        (n->rec >= 0 && d->memops[n->rec].by_helper)) {
        /*
         * Either the note and the op disagree about the direction, or the
         * note was already spent on a previous instruction -- both mean the
         * two streams are no longer in step, and the record this would fill
         * would describe a different access.  The third test asks the same
         * question of CP1's records: a helper-stated access has no note, so
         * a note whose slot now holds one has landed on the wrong record.
         */
        d->memops_unnoted = 1;
        return -1;
    }
    if (n->rec < 0 && n->alt_of >= 0) {
        /*
         * A SECOND EMISSION of one architectural access -- the peeled last
         * iteration of a self-looping string operation; see
         * insn_dataflow_note_path_alt().  It fills the record its
         * counterpart filled rather than allocating one, because the wire's
         * slot count is how many accesses ONE EXECUTION performs and this is
         * the same access on the path the first emission does not take.
         *
         * IT CONTRIBUTES NO PROVENANCE, and that is a decision with a
         * reason.  The peeled copy reads the address register AFTER the loop
         * body advanced it, so its temp chain names the induction the loop
         * added -- on i386 `rep stosq` the direction flag reaches the
         * address that way.  That is a CROSS-ITERATION edge, and the wire
         * publishes one entry per iteration with the pointer register in
         * both its source and its destination list, so the register chain
         * already carries it.  Merging it into THIS access's address would
         * state that one iteration's store address depends on the flag that
         * advances the pointer for the NEXT one -- and on the four targets
         * here it also names an env field with no architectural word, which
         * refuses the whole address family and loses the register the
         * instruction genuinely addresses through.  The first emission is
         * the access as one execution performs it.
         *
         * The counterpart must already HAVE a record and agree about
         * direction and width.  When it does not -- the op stream reached
         * this emission without reaching the first, or the emitter's claim
         * that they are one access does not hold -- the note falls through
         * to the allocation below and is reported as an access of its own.
         * An unmatched alternate is over-reported, never dropped.
         */
        const DfMemopNote *prim = &df_memop[n->alt_of];

        if (prim->rec >= 0 && prim->rec < (int)d->n_memops &&
            prim->is_store == store && prim->size == n->size) {
            n->rec = prim->rec;
            return store ? -1
                         : (int)(INSN_DF_MEMOP_PROV_BASE + n->rec);
        }
    }
    if (n->rec < 0) {
        const void *addr_ts = n->addr_ts;

        if (d->n_memops >= INSN_DF_MAX_MEMOPS) {
            d->memops_overflow = 1;
            return -1;
        }
        /*
         * Resolve the address through the aliases stated BEFORE this note,
         * newest first.  See insn_dataflow_note_addr_alias(): the three
         * store-conditional lowerings hand the cmpxchg the reservation
         * monitor, so without this the address provenance is the monitor --
         * a name no guest instruction writes -- and the register the
         * instruction actually addresses through is absent.
         */
        for (unsigned k = n->alias_n; k-- > 0; ) {
            if (df_alias[k].alias_ts == addr_ts) {
                addr_ts = df_alias[k].real_ts;
                break;
            }
        }
        if (n->alias_dropped) {
            /*
             * An alias this access might have needed was lost to overflow.
             * The address set could be the monitor's rather than the guest's
             * and there is no way to tell which from here, so the access is
             * reported as unaccounted instead of published as though the
             * substitution had been applied.
             */
            d->memops_unnoted = 1;
        }
        n->rec = (int)d->n_memops++;
        m = &d->memops[n->rec];
        m->is_store = store;
        m->size = n->size > UINT8_MAX ? UINT8_MAX : (uint8_t)n->size;
        df_prov_add_temps(m->addr_prov, addr_ts, 1);
        df_fold_add_srcs(m->addr_prov, addr_ts, 1, n->fold_n);
        if (store) {
            df_prov_add_temps(m->data_prov, n->val_ts, n->nval);
            /*
             * A register the emitter folded to a translation-time constant,
             * if that is what the data operand was.  Applied to BOTH halves
             * of the access because the note is a fact about the TEMP and not
             * about which parameter of tcg_gen_qemu_st_* it landed in; the
             * address half has no stated occupant on any target this tree
             * traces, and a rule that held only where an occupant happens to
             * exist would be one more thing to re-derive later.
             * See insn_dataflow_note_folded_reg().
             */
            df_fold_add_srcs(m->data_prov, n->val_ts, n->nval, n->fold_n);
            /*
             * The architectural zero register, if that is what the data
             * operand was.  Its temp holds a constant, so the walk above put
             * NOTHING in data_prov and a consumer would read "this value came
             * from nowhere" for an instruction whose encoding names where it
             * came from.  See insn_dataflow_note_zero_reg().
             */
            if (df_zero_reg_temp(n->val_ts, n->nval, 0, n->zero_n)) {
                df_bit(m->data_prov, INSN_DF_ZERO_PROV_BIT);
            } else if (n->zero_dropped) {
                /*
                 * A note this access might have needed was lost to overflow,
                 * so the absence of the bit is not evidence of absence.  Same
                 * treatment as a dropped address alias: reported unaccounted
                 * rather than published as though the operand had been read.
                 */
                d->memops_unnoted = 1;
            }
        }
        if (n->fold_dropped) {
            /*
             * And the same for a folded-register note lost to overflow: an
             * empty data provenance would otherwise be published as complete,
             * which the format's store-data block reads as "the datum is the
             * instruction's immediate".  Say unaccounted instead.
             */
            d->memops_unnoted = 1;
        }
    }
    return store ? -1 : (int)(INSN_DF_MEMOP_PROV_BASE + n->rec);
}

/*
 * Retire this instruction's load-data bits from the temp table.
 *
 * A load-data bit means "the value load slot k of THIS instruction
 * returned", so it must not survive into the next instruction, where slot k
 * is a different access.  The temps that carry it are the ones this
 * instruction wrote, which is why the range is tracked as it goes rather
 * than rediscovered by scanning all TCG_MAX_TEMPS.
 *
 * Leaving is not the same as dropping.  A value that outlives the
 * instruction that loaded it -- a translator holding a loaded value in a
 * temp across a guest instruction boundary -- keeps a dependency, and it is
 * restated in the only namespace that survives the boundary: the registers
 * that computed the address.  That is what the walk said before this choke
 * point existed, so crossing the boundary costs the precision CP-M added and
 * never a dependency.
 */
static void df_settle_memop_prov(const InsnDataflow *d, size_t lo, size_t hi)
{
    if (lo > hi) {
        return;
    }
    for (size_t i = lo; i <= hi; i++) {
        uint64_t *p;

        if (df_stamp[i] != df_gen) {
            continue;
        }
        p = df_prov[i];
        if (!(p[DF_MEMOP_WORD] & DF_MEMOP_MASK)) {
            continue;
        }
        for (unsigned k = 0; k < d->n_memops; k++) {
            if (df_test(p, INSN_DF_MEMOP_PROV_BASE + k)) {
                df_or(p, d->memops[k].addr_prov);
            }
        }
        p[DF_MEMOP_WORD] &= ~DF_MEMOP_MASK;
    }
}

/*
 * Walk one instruction's ops: [first, end).
 *
 * @marker is the INDEX_op_insn_start op that opens this instruction, which is
 * NOT in [first, end) -- the driver hands the range starting one op later.
 * The zero-register notes need it: an emitter states one from inside a
 * trans_* function, and the common shape is `get_gpr(ctx, a->rs1)` on the
 * first line, before the instruction has emitted an op of its own, so the op
 * the note anchors to is this instruction's insn_start and nothing inside the
 * range would ever match it.
 */
/*
 * Did a writeback emitter say that @op's read of @ts carries only the bits
 * @op does not write?
 *
 * Searched over the whole block's notes rather than over an instruction
 * window, and it is safe to: the key is the CONSUMING OP, which belongs to
 * exactly one instruction and cannot be restated by another.  That is what
 * the zero-register and immediate notes need their anchors and cursors for
 * -- their key is an interned CONSTANT, which every instruction in the block
 * shares.
 */
static bool df_preserve_read(const void *ts, const TCGOp *op)
{
    for (unsigned i = df_n_preserve; i-- > 0; ) {
        const TCGOp *o;
        unsigned n;

        if (df_preserve[i].ts != ts) {
            continue;
        }
        o = df_preserve[i].mark ? QTAILQ_NEXT(df_preserve[i].mark, link)
                                : QTAILQ_FIRST(&tcg_ctx->ops);
        /*
         * Bounded, and the bound is a cost guard rather than a semantic one:
         * an emitter's expansion is a handful of ops, and a range longer than
         * this is not one this note was meant to describe.  Giving up leaves
         * the read an operand read, which is the pessimistic direction.
         */
        for (n = 0; o != NULL && n < 64; o = QTAILQ_NEXT(o, link), n++) {
            if (o == op) {
                return true;
            }
            if (o == df_preserve[i].end) {
                break;
            }
        }
    }
    return false;
}

/*
 * Did an emitter mark the write this op performs as SUPPLYING a value?
 * The same lookup as df_preserve_read() and for the same reason: an
 * emitter's write can expand into several ops and only the range names it.
 */
static bool df_supplied_value(const void *ts, const TCGOp *op)
{
    for (unsigned i = df_n_value; i-- > 0; ) {
        const TCGOp *o;
        unsigned n;

        if (df_value[i].ts != ts) {
            continue;
        }
        o = df_value[i].mark ? QTAILQ_NEXT(df_value[i].mark, link)
                             : QTAILQ_FIRST(&tcg_ctx->ops);
        for (n = 0; o != NULL && n < 64; o = QTAILQ_NEXT(o, link), n++) {
            if (o == op) {
                return true;
            }
            if (o == df_value[i].end) {
                break;
            }
        }
    }
    return false;
}

/*
 * Is a READ of @ts a read of the register a carrier stands for?
 *
 * True only for a declared carrier whose value NO op of the instruction
 * being walked has produced.  That is the whole discriminator, and it is
 * stated at length in insn_dataflow_note_repr_carrier(): inside the
 * instruction that fills it the temp is ordinary scratch -- x86's `cmpxchg`
 * writes a register out of it -- and only a value that OUTLIVED its
 * producing instruction was carried there by the emulator rather than by
 * the machine.
 */
static bool df_carrier_read(const void *ts, unsigned *stands_for)
{
    for (unsigned i = 0; i < df_n_carrier; i++) {
        if (df_carrier[i].ts == ts && !df_carrier[i].defined_here) {
            *stands_for = df_carrier[i].stands_for;
            return true;
        }
    }
    return false;
}

/* An op of the instruction being walked has just written @ts. */
static void df_carrier_defined(const void *ts)
{
    for (unsigned i = 0; i < df_n_carrier; i++) {
        if (df_carrier[i].ts == ts) {
            df_carrier[i].defined_here = true;
            return;
        }
    }
}

static void df_insn(InsnDataflow *d, TCGOp *first, TCGOp *end,
                    const TCGOp *marker, unsigned *memop_cursor,
                    unsigned *zero_cursor, unsigned *imm_cursor,
                    unsigned *disc_cursor, unsigned *encread_cursor)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    uint64_t prov[INSN_DF_REG_WORDS];
    TCGOp *prev_op = NULL;
    /*
     * The temps this instruction gave a LOAD-DATA bit to, as a range.
     *
     * Only those, not every temp it wrote: the range is what
     * df_settle_memop_prov() walks at the end of the instruction, and
     * tracking every write instead made that walk span most of the temp
     * array on instructions that had no load at all -- measured at +24% on
     * the extraction's own time, for a scan that could not find anything.
     */
    size_t tlo = TCG_MAX_TEMPS, thi = 0;
    /*
     * The zero-register notes belonging to THIS instruction: [zero_lo,
     * *zero_cursor).  The cursor is the block's, advanced past a note once
     * the op it anchors to has been walked -- the same discipline the memop
     * cursor runs under -- and the low bound freezes what earlier
     * instructions already claimed.  See DfZeroNote on why a write may not be
     * resolved against a prefix.
     */
    unsigned zero_lo = *zero_cursor;
    /*
     * And the encoded-immediate notes belonging to THIS instruction, on the
     * same discipline.  The low bound is what stops one instruction's
     * immediate from naming the encoding in every later write that touched
     * the same interned constant -- see DfImmNote.
     */
    unsigned imm_lo = *imm_cursor;
    /*
     * And the discarded-write notes, on the same discipline.  The low bound
     * is what keeps one `cmp`'s XZR destination out of every later
     * instruction in the block.
     */
    unsigned disc_lo = *disc_cursor;
    /*
     * And the folded-READ notes, on the same discipline.  The low bound keeps
     * one branch's statement about the instruction pointer out of every later
     * instruction in the block -- see DfEncReadNote.
     */
    unsigned encread_lo = *encread_cursor;

    while (*zero_cursor < df_n_zero && df_zero[*zero_cursor].anchor == marker) {
        (*zero_cursor)++;
    }
    while (*imm_cursor < df_n_imm && df_imm[*imm_cursor].anchor == marker) {
        (*imm_cursor)++;
    }
    while (*disc_cursor < df_n_discard &&
           df_discard[*disc_cursor].anchor == marker) {
        (*disc_cursor)++;
    }
    while (*encread_cursor < df_n_encread &&
           df_encread[*encread_cursor].anchor == marker) {
        (*encread_cursor)++;
    }

    /*
     * The instruction boundary the carrier rule turns on.  Every declared
     * carrier starts this instruction holding whatever the PREVIOUS one left
     * in it, which is the case the rule is about; an op below that writes one
     * flips it back to ordinary dataflow for the rest of this instruction.
     */
    for (unsigned i = 0; i < df_n_carrier; i++) {
        df_carrier[i].defined_here = false;
    }

    for (TCGOp *op = first; op != end; op = QTAILQ_NEXT(op, link)) {
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        unsigned nb_oargs, nb_iargs, idx;
        bool store;
        uint32_t size;
        int ld_field_bit = -1;
        int memop_data_bit = -1;
        uint64_t ld_fwd[INSN_DF_REG_WORDS];
        bool ld_fwd_valid = false;

        /*
         * A note's anchor is the last op its emitter had produced, so the
         * cursor moves past it once that op has been walked.  Done here, on
         * entry to the NEXT op, because the early continues below would
         * otherwise skip it for an anchor that is a call or a discard.
         */
        while (prev_op != NULL && *memop_cursor < df_n_memop &&
               df_memop[*memop_cursor].anchor == prev_op) {
            (*memop_cursor)++;
        }
        while (prev_op != NULL && *zero_cursor < df_n_zero &&
               df_zero[*zero_cursor].anchor == prev_op) {
            (*zero_cursor)++;
        }
        while (prev_op != NULL && *imm_cursor < df_n_imm &&
               df_imm[*imm_cursor].anchor == prev_op) {
            (*imm_cursor)++;
        }
        while (prev_op != NULL && *disc_cursor < df_n_discard &&
               df_discard[*disc_cursor].anchor == prev_op) {
            (*disc_cursor)++;
        }
        while (prev_op != NULL && *encread_cursor < df_n_encread &&
               df_encread[*encread_cursor].anchor == prev_op) {
            (*encread_cursor)++;
        }
        prev_op = op;

        if (op->opc == INDEX_op_insn_start) {
            continue;
        }

        if (op->opc == INDEX_op_call) {
            const DfHelperNote *hn = df_find_helper(op);
            /*
             * CP-H.  Two passes, because the destination's provenance is the
             * union of the SOURCES and the sources are not all known until
             * every argument has been looked at.  The single pass this
             * replaced added a field record as it went, so the first pointer
             * argument -- which for every gvec helper is the DESTINATION --
             * was given a provenance holding only itself: helper_gvec_add8's
             * vd came out depending on vd and on neither vn nor vm.  A missed
             * dependency, in the code whose own comment says a missed
             * dependency is the one error it must not make.
             */
            uint32_t pf_off[DF_MAX_HELPER_FIELDS];
            uint32_t pf_size[DF_MAX_HELPER_FIELDS];
            uint8_t pf_dir[DF_MAX_HELPER_FIELDS];
            unsigned n_pf = 0;
            uint8_t model = INSN_DF_HELPER_EXACT;
            DfHelperCensus *cen = NULL;
            const DfHelperUsage *row = NULL;

            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            d->n_calls++;
            /*
             * TCG's own statement that this call does not come back.  Read
             * here, at the call, rather than inferred later from the block's
             * shape: DISAS_NORETURN suppresses the epilogue entirely, so a
             * walk looking for exit_tb finds NOTHING for a raising
             * instruction and cannot tell it from a block that ran out of
             * ops.  See INSN_DF n_noreturn_calls for what the count is for.
             */
            if (tcg_call_flags(op) & TCG_CALL_NO_RETURN) {
                if (d->n_noreturn_calls < 255) {
                    d->n_noreturn_calls++;
                }
            }

            memset(prov, 0, sizeof(prov));

            /*
             * Pass 1a: everything the op itself states.  The physical
             * arguments are walked -- not the note's logical ones -- because
             * an i128 argument is two temps with two provenances and only the
             * physical list names both.
             */
            for (unsigned i = 0; i < nb_iargs; i++) {
                TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
                const uint64_t *fwd;

                df_or(prov, df_prov_of(ts - s->temps));
                if (df_reg(ts, &idx)) {
                    /* See df_written_prov(): a read-back of this
                     * instruction's own result is not an operand fetch. */
                    fwd = df_written_prov(d, idx);
                    if (fwd) {
                        df_or(prov, fwd);
                    } else {
                        df_bit(d->rd, idx);
                        df_ord_read(d, INSN_DF_ORD_GLOBAL, idx);
                        df_bit(prov, idx);
                    }
                }
            }

            /*
             * Pass 1b: the pointer arguments, and what the emitter said about
             * them.  A pointer into env is how a vector register, an x87
             * stack slot or an FP status word reaches a helper -- the state
             * the TCG-global namespace does not name.  tcg_env itself is not
             * an operand: it is the first argument of nearly every helper
             * there is.
             */
            if (hn) {
                /*
                 * Before the operands: is the helper's footprint bounded at
                 * all?
                 *
                 * TCG_CALL_NO_READ_GLOBALS / _NO_WRITE_GLOBALS are QEMU's own
                 * statement about a helper, and the register allocator acts on
                 * them: without them tcg_liveness_analysis() does
                 * la_global_kill() -- every global is written -- or
                 * la_global_sync() -- every global is read (tcg/tcg.c).  The
                 * op list names none of those accesses, so for such a helper
                 * the extracted read and write sets are SHORT OF THE TRUTH,
                 * not merely coarse, and calling the instruction exactly
                 * described would be the one error this file says it must not
                 * make.  It is labelled instead; widening the sets to every
                 * global is a change to what the extraction PUBLISHES and
                 * belongs behind its own measurement.
                 */
                if (df_censusing()) {
                    qemu_mutex_lock(&df_census_lock);
                    cen = df_census_row(hn->name, hn->flags, hn->nargs);
                    if (cen) {
                        cen->calls++;
                        if (!(hn->flags & TCG_CALL_NO_READ_GLOBALS)) {
                            cen->reasons |= DF_CR_NO_RWG;
                        }
                        if (!(hn->flags & (TCG_CALL_NO_WRITE_GLOBALS |
                                           TCG_CALL_NO_READ_GLOBALS))) {
                            cen->reasons |= DF_CR_NO_WRG;
                        }
                        if (hn->args_overflow) {
                            cen->reasons |= DF_CR_ARGS_OVERFLOW;
                        }
                    }
                }
                row = df_helper_usage_row(hn->name);
                /*
                 * The written-down row answers BOTH halves of the opacity at
                 * once, and it has to, because they are one question.  QEMU's
                 * globals live in CPUArchState -- cpu_regs[] on x86 is
                 * offsetof(CPUX86State, regs[R_EAX]) and so on -- so a
                 * complete enumeration of the members a helper touches is
                 * already a statement about every global it touches.  Having
                 * one and still calling the helper unbounded because the
                 * DECLARATION omits TCG_CALL_NO_RWG would be preferring the
                 * flag over the body the flag summarises.
                 */
                if (!row || !row->env_bounded) {
                    if (!(hn->flags & TCG_CALL_NO_READ_GLOBALS)) {
                        model = MAX(model, INSN_DF_HELPER_OPAQUE);
                        d->n_helper_unbounded += d->n_helper_unbounded < 255;
                    }
                }
                /*
                 * CP1 -- the guest memory the helper reaches ITSELF.
                 *
                 * There is no qemu_ld/qemu_st op to match these against;
                 * that is the whole reason they are here.  So they are
                 * appended to the access list at the CALL, which is where
                 * they happen in emission order, and each carries how much
                 * of itself the row could state.
                 */
                for (unsigned k = 0; row && k < row->n_acc; k++) {
                    const DfHelperAccess *ha = &row->acc[k];
                    InsnDataflowMemop *m;
                    const TCGTemp *ats = NULL, *dts = NULL;

                    if (d->n_memops >= INSN_DF_MAX_MEMOPS) {
                        d->memops_overflow = 1;
                        break;
                    }
                    if (ha->addr_arg != DF_HA_NO_ARG &&
                        ha->addr_arg < hn->nargs) {
                        ats = hn->arg[ha->addr_arg];
                    }
                    if (ha->data_arg != DF_HA_NO_ARG &&
                        ha->data_arg < hn->nargs) {
                        dts = hn->arg[ha->data_arg];
                    }
                    m = &d->memops[d->n_memops++];
                    m->is_store = (ha->dir & INSN_DF_WR) != 0;
                    m->size = ha->size;
                    m->by_helper = 1;
                    m->count_unbounded = ha->count_unbounded;
                    d->memops_by_helper += d->memops_by_helper < 255;
                    if (ha->count_unbounded) {
                        d->memops_count_unbounded = 1;
                    }
                    if (ats) {
                        df_prov_add_temps(m->addr_prov, ats, 1);
                    } else {
                        /*
                         * Not "no dependency": the address never travelled
                         * through an argument, so nothing here can name it.
                         * Said, rather than published as an empty set.
                         */
                        m->addr_unstated = 1;
                        d->memops_addr_unstated = 1;
                    }
                    if (m->is_store) {
                        if (dts) {
                            df_prov_add_temps(m->data_prov, dts, 1);
                        } else {
                            m->data_unstated = 1;
                            d->memops_data_unstated = 1;
                        }
                    }
                    /*
                     * A helper access that both reads and writes is ONE
                     * access in the row and two on the wire's terms.  The
                     * read half is added beside it rather than folded into
                     * the store, because a consumer separating load-to-use
                     * from store-to-load needs them apart.
                     */
                    if ((ha->dir & (INSN_DF_RD | INSN_DF_WR)) ==
                        (INSN_DF_RD | INSN_DF_WR)) {
                        if (d->n_memops >= INSN_DF_MAX_MEMOPS) {
                            d->memops_overflow = 1;
                            break;
                        }
                        m = &d->memops[d->n_memops++];
                        m->is_store = 0;
                        m->size = ha->size;
                        m->by_helper = 1;
                        m->count_unbounded = ha->count_unbounded;
                        d->memops_by_helper += d->memops_by_helper < 255;
                        if (ats) {
                            df_prov_add_temps(m->addr_prov, ats, 1);
                        } else {
                            m->addr_unstated = 1;
                            d->memops_addr_unstated = 1;
                        }
                    }
                }
                for (unsigned k = 0; k < hn->nargs; k++) {
                    const TCGTemp *ts = hn->arg[k];
                    int64_t eo;
                    uint8_t dir;
                    uint32_t extent;
                    int bit;

                    if (ts == NULL || hn->typecode[k] != dh_typecode_ptr) {
                        continue;
                    }
                    if (cen && k < 32) {
                        cen->ptr_args |= 1u << k;
                    }
                    if (ts == env_ts) {
                        /*
                         * The whole CPU state pointer.  Nothing in the call
                         * says which of CPUArchState the helper reaches
                         * through it, so its operand set is not stated -- it
                         * is merely not enumerated.  Treating this as "no
                         * operand" is what made a helper-implemented x87
                         * instruction come out looking exactly described:
                         * helper_fsin(env) has no other argument at all, and
                         * every access it makes to the x87 stack is invisible
                         * here.
                         */
                        if (row && row->env_bounded) {
                            /*
                             * The member list stands in for the pointer.  Each
                             * one becomes a field record with its own
                             * direction, so a consumer sees `helper_fldenv
                             * writes fpuc, fpus, fpstt and fptags` rather than
                             * `something happened inside a call`.
                             */
                            for (unsigned q = 0; q < row->n_env; q++) {
                                if (row->env[q].kind == DF_HF_XLAT) {
                                    continue;
                                }
                                if (n_pf >= DF_MAX_HELPER_FIELDS) {
                                    model = MAX(model, INSN_DF_HELPER_OPAQUE);
                                    break;
                                }
                                pf_off[n_pf] = row->env[q].off;
                                pf_size[n_pf] = row->env[q].size;
                                pf_dir[n_pf] = row->env[q].dir;
                                n_pf++;
                                /*
                                 * A member the row could not narrow to an
                                 * element is still a footprint the helper
                                 * has; it is published as the whole file and
                                 * the instruction is labelled, because a
                                 * consumer that REPLACES its own list with
                                 * this one must not read "the file" as "these
                                 * registers".
                                 */
                                if (row->env[q].unbounded) {
                                    d->helper_writes_unbounded |=
                                        (row->env[q].dir & INSN_DF_WR) != 0;
                                }
                                if (row->env[q].dir & INSN_DF_RD) {
                                    int b = df_intern(row->env[q].off,
                                                      row->env[q].size);

                                    if (b >= 0) {
                                        df_bit(prov, (unsigned)b);
                                    }
                                }
                            }
                            continue;
                        }
                        model = MAX(model, INSN_DF_HELPER_OPAQUE);
                        d->n_helper_unbounded += d->n_helper_unbounded < 255;
                        if (cen) {
                            cen->reasons |= DF_CR_ENV;
                            if (k < 32) {
                                cen->env_args |= 1u << k;
                            }
                        }
                        continue;
                    }
                    eo = df_envoff_of(ts - s->temps);
                    if (eo == INSN_DF_NOT_ENV || eo < 0) {
                        /*
                         * A pointer whose value is not tcg_env plus a
                         * constant: a fpstatus pointer passed down from the
                         * translator, a guest pointer.  Nothing about the
                         * region is known, so nothing is claimed about it --
                         * but the helper does reach state through it, so the
                         * instruction cannot be called exactly described.
                         */
                        model = MAX(model, INSN_DF_HELPER_OPAQUE);
                        d->n_helper_unbounded += d->n_helper_unbounded < 255;
                        if (cen) {
                            cen->reasons |= DF_CR_PTR;
                        }
                        continue;
                    }
                    extent = 0;
                    dir = 0;
                    /*
                     * The gvec constructors pass their operand pointers as
                     * the helper's first arguments, in order, so operand k IS
                     * argument k.  Matching by OFFSET instead would be wrong
                     * whenever two operands name the same register, which is
                     * the ordinary shape of an accumulate: aarch64 sdot is
                     * emitted as gvec_4_ool(rd, rn, rm, rd), and an
                     * offset-keyed lookup answers the fourth argument -- a
                     * genuine READ of rd -- with the first one's DESTINATION
                     * role.  Measured: it double-counted sdot's unresolved
                     * operands as 2 where there is 1.
                     */
                    if (hn->has_gvec && k < hn->gvec_n) {
                        if (hn->gvec_off[k] != (uint32_t)eo) {
                            /*
                             * Argument k is not the pointer the constructor
                             * built for operand k, so the correspondence this
                             * code rests on does not hold for this helper.
                             * Describe it with nothing rather than with
                             * another operand's role.
                             */
                            model = MAX(model, INSN_DF_HELPER_OPAQUE);
                            if (cen) {
                                cen->reasons |= DF_CR_GVEC_MISMATCH;
                            }
                        } else {
                            dir = hn->gvec_dir[k];
                            extent = hn->gvec_oprsz;
                        }
                    }
                    if (dir == 0 && !df_helper_usage_of(hn->name, k, &dir)) {
                        dir = 0;
                    }
                    /*
                     * THE EXTENT, when the constructor did not state one.
                     *
                     * A gvec call carries its operand size and this is not
                     * reached; every other helper carried nothing, and a
                     * range of width 0 resolves to no register at all --
                     * insn_dataflow_field_reg() refuses it, correctly, since
                     * a width it was not told cannot be shown to stay inside
                     * one register.  The row's figure is sizeof() the type
                     * the helper's own signature declares, so an SSE helper
                     * handed &env->xmm_regs[n] now reaches the wire as a
                     * write of THAT vector register instead of as an
                     * unnamed byte range.
                     */
                    if (extent == 0) {
                        extent = df_helper_argsize(row, k);
                    }
                    if (dir == 0) {
                        /* Nobody stated it.  Both directions, and say so. */
                        dir = INSN_DF_RD | INSN_DF_WR;
                        model = MAX(model, INSN_DF_HELPER_APPROX);
                        d->n_helper_unknown += d->n_helper_unknown < 255;
                        if (cen) {
                            cen->unknown_pairs++;
                            if (k < 32) {
                                cen->unknown_args |= 1u << k;
                            }
                        }
                    } else if ((dir & INSN_DF_WR) && !(dir & INSN_DF_RD) &&
                               !df_helper_usage_of(hn->name, k, &dir)) {
                        /*
                         * The constructor stated a DESTINATION.  Whether the
                         * helper also READS it -- an accumulate -- is the
                         * per-helper fact, and with no row for it the read is
                         * recorded and the instruction labelled.  The extent
                         * stays exact either way, which is the part the walk
                         * never had.
                         */
                        dir |= INSN_DF_RD;
                        model = MAX(model, INSN_DF_HELPER_APPROX);
                        d->n_helper_unknown += d->n_helper_unknown < 255;
                        if (cen) {
                            cen->unknown_pairs++;
                            if (k < 32) {
                                cen->unknown_args |= 1u << k;
                            }
                        }
                    } else if (cen && k < 32) {
                        cen->stated_args |= 1u << k;
                    }
                    if (n_pf < DF_MAX_HELPER_FIELDS) {
                        pf_off[n_pf] = (uint32_t)eo;
                        pf_size[n_pf] = extent;
                        pf_dir[n_pf] = dir;
                        n_pf++;
                    }
                    if (dir & INSN_DF_RD) {
                        bit = df_intern((uint32_t)eo, extent);
                        if (bit >= 0) {
                            df_bit(prov, (unsigned)bit);
                        }
                    }
                }
                if (hn->args_overflow) {
                    model = MAX(model, INSN_DF_HELPER_OPAQUE);
                }
                if (df_census_on) {
                    /*
                     * Rewritten in full on every call rather than at exit.
                     * qemu-user leaves through _exit() -- exit_group() calls
                     * preexit_cleanup() and then _exit(), which runs no
                     * atexit handler and flushes no stdio -- so an at-exit
                     * dump produces NO FILE AT ALL and the measurement
                     * silently does not exist.  Observed: the first cut wrote
                     * nothing on all four ISAs.  The cost is bounded by
                     * TRANSLATIONS of a helper call, not executions of one --
                     * about two thousand on this workload -- and the
                     * instrument is off unless asked for.
                     */
                    df_census_dump_locked();
                    qemu_mutex_unlock(&df_census_lock);
                    cen = NULL;
                }
            } else {
                /*
                 * No note: the note array overflowed, or a call reached the
                 * op list by a route tcg_gen_callN does not serve.  Fall back
                 * to what the walk alone can say, and label the instruction
                 * with what that is worth.
                 */
                for (unsigned i = 0; i < nb_iargs; i++) {
                    TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
                    int64_t eo;

                    if (ts == env_ts) {
                        continue;
                    }
                    eo = df_envoff_of(ts - s->temps);
                    if (eo != INSN_DF_NOT_ENV && eo >= 0) {
                        int bit = df_intern((uint32_t)eo, 0);

                        if (bit >= 0) {
                            df_bit(prov, (unsigned)bit);
                        }
                        if (n_pf < DF_MAX_HELPER_FIELDS) {
                            pf_off[n_pf] = (uint32_t)eo;
                            pf_size[n_pf] = 0;
                            pf_dir[n_pf] = INSN_DF_RD | INSN_DF_WR;
                            n_pf++;
                        }
                    }
                }
                model = MAX(model, INSN_DF_HELPER_OPAQUE);
                d->n_helper_unbounded += d->n_helper_unbounded < 255;
            }

            /* Pass 2: publish, now that the source set is complete. */
            for (unsigned i = 0; i < n_pf; i++) {
                df_add_field(d, pf_off[i], pf_size[i], pf_dir[i],
                             (pf_dir[i] & INSN_DF_WR) ? prov : NULL);
            }
            /*
             * A footprint that did not FIT is a footprint that was not
             * published, and an instruction whose field list was truncated
             * cannot be called exactly described no matter how complete the
             * row behind it was.  Without this the enumeration would trade
             * one silent short set for another.
             */
            if (d->fields_overflow) {
                model = MAX(model, INSN_DF_HELPER_OPAQUE);
            }

            for (unsigned i = 0; i < nb_oargs; i++) {
                TCGTemp *ts = arg_temp(op->args[i]);

                if (df_reg(ts, &idx)) {
                    df_bit(d->wr, idx);
                    df_ord_write(d, INSN_DF_ORD_GLOBAL, idx);
                    df_add_write(d, idx, prov, df_supplied_value(ts, op));
                } else {
                    size_t ti = ts - s->temps;

                    df_or(df_prov_of(ti), prov);
                    df_set_defop(ti, op);
                    if (prov[DF_MEMOP_WORD] & DF_MEMOP_MASK) {
                        tlo = MIN(tlo, ti);
                        thi = MAX(thi, ti);
                    }
                }
            }
            if (model > d->helper_model) {
                d->helper_model = model;
            }
            continue;
        }

        /*
         * discard names its argument as an output but is not a write: it is
         * TCG being told the temp's value is dead, which on x86 is how the
         * flag fields an instruction does not define are retired.  Counting
         * it as a write would put cc_src2 in the write set of every add.
         */
        if (op->opc == INDEX_op_discard) {
            TCGTemp *ts = arg_temp(op->args[0]);

            if (df_reg(ts, &idx)) {
                df_bit(d->kill, idx);
            } else {
                df_set_envoff(ts - s->temps, INSN_DF_NOT_ENV);
            }
            continue;
        }

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;

        if (df_ldst(op, &store, &size)) {
            TCGTemp *bts = arg_temp(op->args[1]);
            int64_t bo = bts == env_ts ? 0 : df_envoff_of(bts - s->temps);

            if (bo != INSN_DF_NOT_ENV) {
                int64_t eo = bo + (int64_t)op->args[2];

                if (eo < 0) {
                    /*
                     * A NEGATIVE env offset is not guest state.  env points
                     * at CPUArchState, which sits at sizeof(CPUState) inside
                     * ArchCPU, so everything below it is QEMU's own
                     * bookkeeping -- and one of those slots is the
                     * INSTRUMENT'S: plugin_gen_mem_callbacks_i64() emits
                     *
                     *     st_i64 <loaded value>, env,
                     *            offsetof(CPUState, neg.plugin_mem_value_low)
                     *            - sizeof(CPUState)
                     *
                     * so that qemu_plugin_mem_value() can read it
                     * (tcg/tcg-op-ldst.c:213).  Falling through to the
                     * generic argument walk read that store's data operand
                     * as an input of the guest instruction, which on the
                     * targets whose translator loads STRAIGHT INTO A GLOBAL
                     * -- aarch64 and riscv64 -- made every load name its own
                     * destination as a source.  MEASURED on `ld a2,0(t6)`
                     * with a2 never read again: `D r reg=x12/a2` beside
                     * `D w reg=x12/a2 from=L0`.  x86_64 and mipsel load into
                     * a temp first and were untouched, which is why the
                     * defect read as an ISA quirk rather than as what it is.
                     *
                     * A dependency that exists only because someone was
                     * watching is the one error this extractor must not
                     * make: it is the map that is meant to REPLACE Capstone,
                     * and it would have published the edge on every load.
                     */
                    continue;
                }
                if (eo >= 0) {
                    if (store) {
                        /*
                         * The value's provenance is the field's provenance:
                         * this is where a vector register's write gets the
                         * same account of itself a GPR's write already had.
                         */
                        TCGTemp *vts = arg_temp(op->args[0]);

                        df_add_field(d, (uint32_t)eo, size, INSN_DF_WR,
                                     df_prov_of(vts - s->temps));
                    } else {
                        if (df_field_forward(d, (uint32_t)eo, size, ld_fwd)) {
                            ld_fwd_valid = true;
                        } else {
                            ld_field_bit = df_intern((uint32_t)eo, size);
                        }
                        df_add_field(d, (uint32_t)eo, size, INSN_DF_RD, NULL);
                    }
                }
            }
        }

        switch (op->opc) {
        case INDEX_op_qemu_ld_i32:
        case INDEX_op_qemu_ld_i64:
        case INDEX_op_qemu_ld_i128:
            d->n_mem_rd++;
            memop_data_bit = df_memop_apply(d, false, memop_cursor);
            break;
        case INDEX_op_qemu_st_i32:
        case INDEX_op_qemu_st_i64:
        case INDEX_op_qemu_st8_i32:
        case INDEX_op_qemu_st_i128:
            d->n_mem_wr++;
            (void)df_memop_apply(d, true, memop_cursor);
            break;
        default:
            break;
        }

        memset(prov, 0, sizeof(prov));
        for (unsigned i = 0; i < nb_iargs; i++) {
            TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
            unsigned carried;

            /*
             * A REPRESENTATION CARRIER holding a value this instruction did
             * not produce is the register it re-expresses, and NOT the place
             * that register's value came from an instruction ago.  x86 caches
             * the subtract family's first operand in DisasContext::cc_srcT so
             * that CF stays computable, and chasing that temp's provenance
             * published the compared GPR as a source of every later `cmovb`,
             * `seta` and `setb` -- an edge two independent references caught
             * and the architecture does not define.
             *
             * The register goes in, the stale origin stays out; nothing else
             * about the read changes.  See insn_dataflow_note_repr_carrier().
             */
            if (df_carrier_read(ts, &carried)) {
                df_bit(d->rd, carried);
                df_ord_read(d, INSN_DF_ORD_GLOBAL, carried);
                df_bit(prov, carried);
                if (d->n_repr_carrier < UINT8_MAX) {
                    d->n_repr_carrier++;
                }
                continue;
            }

            df_or(prov, df_prov_of(ts - s->temps));
            /*
             * A REGISTER THE EMITTER FOLDED, that this op is really reading.
             * The note says the temp holds that register's value; the op
             * reading it is what makes the register a SOURCE of this
             * instruction, and without this the read set is short by exactly
             * the register the encoding named -- every RIP-relative address on
             * x86, and the return address a call pushes.
             *
             * Into the read set and the ordered list only.  NOT into @prov:
             * whether a folded constant is a dependency EDGE is the consumer's
             * call, and a bit here would be this file making it -- and would
             * move destination masks the wire already publishes.
             * See insn_dataflow_note_folded_reg().
             */
            {
                const TCGTemp *fsrc = df_fold_src_of(ts, df_n_fold);
                unsigned fidx;

                if (fsrc != NULL && df_reg(fsrc, &fidx)) {
                    df_bit(d->rd, fidx);
                    df_ord_read(d, INSN_DF_ORD_GLOBAL, fidx);
                }
            }
            /*
             * THE INSTRUCTION'S OWN ENCODED IMMEDIATE, stated by the decoder
             * that materialised it.  Tested on its own rather than as a branch
             * of the chain below, because the three facts are not exclusive:
             * on a target whose zero register is a constant, `li a0,0`
             * resolves BOTH the zero-register note and the immediate note to
             * the one interned temp, and both are true of it -- the encoding
             * names x0 and the encoding names 0.
             *
             * Bounded to this instruction's notes, which is the whole reason
             * the notes carry an anchor: immediates intern by value and a
             * prefix window would name the encoding in every later write that
             * touched the same small integer.
             */
            if (df_imm_temp(ts, imm_lo, *imm_cursor)) {
                df_bit(prov, INSN_DF_IMM_PROV_BIT);
                /*
                 * The note had somewhere to go.  Without this a consumer
                 * cannot separate "the immediate does not feed this
                 * destination" from "QEMU folded the immediate away before
                 * any op saw it" -- `addi rd,rs,0` becomes a mov -- and the
                 * second is the emulator's optimisation, which R7.3 forbids
                 * publishing as the machine's.
                 */
                d->imm_reached = 1;
            }
            if (df_reg(ts, &idx)) {
                /*
                 * A READ-BACK OF THIS INSTRUCTION'S OWN RESULT is not an
                 * operand fetch, and naming the register here is what put
                 * every in-place lowering's destination in its own
                 * provenance.  See df_written_prov().
                 */
                const uint64_t *fwd;

                if (df_preserve_read(ts, op)) {
                    /*
                     * THE CARRIER NOTE.  The emitter that produced this op
                     * said the register is here only to carry the bits the
                     * write does not reach -- R7.1: "the fact that a
                     * register's upper contents may not be modified does not
                     * imply it is a source AND a destination for the
                     * instruction unless the instruction specifically takes
                     * it as a source."  It contributes neither to the read
                     * set nor to the provenance.  See DfPreserveNote.
                     */
                    continue;
                }
                fwd = df_written_prov(d, idx);
                if (fwd) {
                    df_or(prov, fwd);
                } else {
                    df_bit(d->rd, idx);
                    df_ord_read(d, INSN_DF_ORD_GLOBAL, idx);
                    df_bit(prov, idx);
                }
            } else if (df_zero_reg_temp(ts, 1, zero_lo, *zero_cursor)) {
                /*
                 * The architectural ZERO REGISTER, stated by the accessor
                 * that resolved the operand.  Its temp holds a constant, so
                 * the walk above put NOTHING in @prov and a write fed by it
                 * would arrive at a consumer as a value that came from
                 * nowhere -- which for a destination is indistinguishable
                 * from the instruction's own immediate, and R7.3 rules that
                 * the register the encoding names is not the emulator's to
                 * drop.  The bit goes in the provenance and not in @d->rd:
                 * the read set is indexed by TCG global and this register has
                 * none, which is the whole reason it needs a bit of its own.
                 *
                 * Bounded to the notes this instruction took.  See
                 * DfZeroNote -- a prefix would name the zero register in
                 * every write after the first instruction that read it.
                 */
                df_bit(prov, INSN_DF_ZERO_PROV_BIT);
                /*
                 * AND INTO THE ORDERED LIST, which is the one place it can
                 * go.  It has no TCG global, so @d->rd cannot hold it -- and
                 * a consumer building a source LIST from the read set alone
                 * is short by exactly the register the encoding named, which
                 * R7.3 rules is not the emulator's to drop.  The bitmap's
                 * inability to say it is why the list is not a permutation
                 * of the bitmap.
                 */
                df_ord_read(d, INSN_DF_ORD_ZERO, 0);
            }
        }

        /*
         * THE INSTRUCTION'S OWN ENCODED FIELD, stated BY VALUE because no
         * temp ever carried it.  `tcg_gen_extract_i64(rd, rn, pos, len)`
         * puts the bitfield position and length in op->args, where the
         * argument walk above cannot see them and where there is nothing to
         * hang a provenance on -- so the decoder said so at the op, and the
         * bit goes into the op's provenance exactly where the temp form's
         * would have gone.  See insn_dataflow_note_encoded_imm_value().
         *
         * Placed before the load rule below so that rule still wins: a value
         * that came out of memory came out of memory, whatever arithmetic
         * the address took.
         */
        if (df_imm_operand_at(op, *imm_cursor)) {
            df_bit(prov, INSN_DF_IMM_PROV_BIT);
            d->imm_reached = 1;
        }

        /*
         * What a load returned did not come from the registers that computed
         * its address -- it came from memory, and the address is a separate
         * dependency with a separate latency.  The op cannot say so (its
         * only input IS the address temp), so the emitter's note does: the
         * value's provenance becomes the bit standing for this access, and
         * the address registers stay where they belong, in the access's own
         * addr_prov and in the instruction's read set.
         */
        if (memop_data_bit >= 0) {
            memset(prov, 0, sizeof(prov));
            df_bit(prov, (unsigned)memop_data_bit);
        }

        for (unsigned i = 0; i < nb_oargs; i++) {
            TCGTemp *ts = arg_temp(op->args[i]);

            if (df_reg(ts, &idx)) {
                df_bit(d->wr, idx);
                df_ord_write(d, INSN_DF_ORD_GLOBAL, idx);
                df_add_write(d, idx, prov, df_supplied_value(ts, op));
            } else {
                size_t ti = ts - s->temps;
                uint64_t *dp = df_prov_of(ti);

                df_carrier_defined(ts);
                if (prov[DF_MEMOP_WORD] & DF_MEMOP_MASK) {
                    tlo = MIN(tlo, ti);
                    thi = MAX(thi, ti);
                }
                memcpy(dp, prov, sizeof(prov));
                /*
                 * This op is now the temp's definition, which is what a
                 * folded-register note taken against an earlier one has to
                 * be tested against.  See DfFoldNote::anchor.
                 */
                df_set_defop(ti, op);
                /*
                 * A load's value came from the field it loaded, which the
                 * op's own inputs do not say -- they name the base pointer.
                 * Without this a value read out of the vector file looks like
                 * it came from nowhere, and every instruction operating on it
                 * would report a broken dependency chain it does not have.
                 */
                if (ld_field_bit >= 0) {
                    df_bit(dp, (unsigned)ld_field_bit);
                } else if (ld_fwd_valid) {
                    /* The scratch's own account, from the write that filled
                     * it -- see df_field_forward(). */
                    df_or(dp, ld_fwd);
                }
            }
        }

        /*
         * Track temps whose value is tcg_env plus a constant, and temps whose
         * value is a constant.  Only mov and add-of-a-constant can produce
         * one; anything else writing a tracked temp stops tracking it, so the
         * map never outlives the fact.
         */
        if (nb_oargs == 1) {
            TCGTemp *dts = arg_temp(op->args[0]);
            size_t di = dts - s->temps;
            int64_t v = INSN_DF_NOT_ENV;

            if (op->opc == INDEX_op_mov_i64 || op->opc == INDEX_op_mov_i32) {
                TCGTemp *a = arg_temp(op->args[1]);

                v = a == env_ts ? 0 : df_envoff_of(a - s->temps);
            } else if (op->opc == INDEX_op_add_i64 ||
                       op->opc == INDEX_op_add_i32) {
                TCGTemp *a = arg_temp(op->args[1]);
                TCGTemp *b = arg_temp(op->args[2]);
                int64_t ao = a == env_ts ? 0 : df_envoff_of(a - s->temps);
                int64_t bo = b == env_ts ? 0 : df_envoff_of(b - s->temps);

                if (ao != INSN_DF_NOT_ENV && b->kind == TEMP_CONST) {
                    v = ao + b->val;
                } else if (bo != INSN_DF_NOT_ENV && a->kind == TEMP_CONST) {
                    v = bo + a->val;
                }
            }
            df_set_envoff(di, v);
        }
    }

    while (prev_op != NULL && *memop_cursor < df_n_memop &&
           df_memop[*memop_cursor].anchor == prev_op) {
        (*memop_cursor)++;
    }
    while (prev_op != NULL && *zero_cursor < df_n_zero &&
           df_zero[*zero_cursor].anchor == prev_op) {
        (*zero_cursor)++;
    }
    while (prev_op != NULL && *imm_cursor < df_n_imm &&
           df_imm[*imm_cursor].anchor == prev_op) {
        (*imm_cursor)++;
    }
    while (prev_op != NULL && *disc_cursor < df_n_discard &&
           df_discard[*disc_cursor].anchor == prev_op) {
        (*disc_cursor)++;
    }
    while (prev_op != NULL && *encread_cursor < df_n_encread &&
           df_encread[*encread_cursor].anchor == prev_op) {
        (*encread_cursor)++;
    }
    /*
     * THE DISCARDED WRITES, resolved LAST because their provenance is a
     * property of the finished instruction and not of any one op.
     *
     * The value a discarded destination receives is whatever @ts holds when
     * the instruction is over: for AArch64's throwaway XZR temp that is what
     * the flag-setting op put there, and for a global the instruction only
     * read it is the register itself.  Resolving it during the op loop would
     * mean guessing which op is the last writer, which is precisely the
     * question `cmp`'s lowering -- result into the temp, flags into four
     * others -- gives no stable answer to.
     */
    /*
     * THE FOLDED READS -- registers the encoding named as sources for which
     * the emitter produced no temp, so the op walk above could not have seen
     * them.  Resolved here, after the walk, which puts them at the END of the
     * ordered read list: there is no op to interleave them at, and the
     * ordering contract reserves exactly that position for a member no op
     * names.
     *
     * Both the bitmap and the list, because they answer different questions
     * and a member in one but not the other is a contradiction a consumer
     * would have to guess its way out of.  Nothing goes into any provenance:
     * whether a folded operand is a dependency EDGE is the consumer's decision
     * (see the header), and a bit in a write's provenance would be this file
     * making it.
     */
    if (df_encread_overflow) {
        /*
         * Block-wide and deliberately over-broad, like the other note caps: a
         * dropped statement is a SOURCE missing from the list and nothing here
         * can say which instruction lost it.  The list is refused rather than
         * published short -- the one error direction this file treats as an
         * error.
         */
        d->rd_ord_overflow = 1;
    }
    for (unsigned i = encread_lo; i < *encread_cursor; i++) {
        unsigned idx;

        if (df_encread[i].name) {
            /*
             * A register with no global and no env range: its NAME is its
             * identity, so it goes into named_reads[] and reaches the ordered
             * read list from there.  No bit in @d->rd -- there is no global
             * to set one for -- and no provenance, because the instruction
             * depends on the value rather than computing it.
             */
            df_add_named_read(d, df_encread[i].name);
        } else if (df_encread[i].env_size) {
            /*
             * A range rather than a register id, so it goes onto the env
             * side -- the same route an ordinary env load takes, which is
             * what lets a declared regfile give it its name downstream.  No
             * provenance: this instruction did not compute the value, it
             * depends on it.
             */
            df_add_field(d, df_encread[i].env_off, df_encread[i].env_size,
                         INSN_DF_RD, NULL);
        } else if (df_encread[i].zero) {
            /*
             * The architectural zero register has no TCG global, so @d->rd
             * cannot hold it and the ordered list is the only place it can go
             * -- the same asymmetry the operand-walk arm lives with.
             */
            df_ord_read(d, INSN_DF_ORD_ZERO, 0);
        } else if (df_reg((const TCGTemp *)df_encread[i].src_ts, &idx)) {
            df_bit(d->rd, idx);
            df_ord_read(d, INSN_DF_ORD_GLOBAL, idx);
        }
    }
    for (unsigned i = disc_lo; i < *disc_cursor; i++) {
        df_add_discard(d, &df_discard[i]);
    }
    /*
     * An instruction whose decoder spoke at all: stated even when the
     * constant never reached an op, because the two facts answer different
     * questions and folding them would put the coverage hole and the
     * emulator's fold under one word again.
     */
    if (*imm_cursor > imm_lo) {
        d->imm_stated = 1;
    }
    /*
     * And whether one of the fields it spoke about is a field the
     * ARCHITECTURE does not define as a dataflow operand -- MIPS' trap and
     * break codes.  Scoped to this instruction's own notes for the reason
     * every note here is: a block of `teq` must not let the first one's
     * statement answer for the rest.
     *
     * A separate flag rather than a third state of the two above, because it
     * is a third FACT: stated-and-folded and stated-and-not-an-operand are
     * opposite claims about the same absent bit, and collapsing them would
     * put the emulator's optimisation and the machine's own definition under
     * one word again -- which is the mistake @imm_reached exists to undo.
     */
    for (unsigned i = imm_lo; i < *imm_cursor; i++) {
        if (df_imm[i].ts == NULL &&
            df_imm[i].role == INSN_DF_IMM_ROLE_NON_DATAFLOW) {
            d->imm_non_dataflow = 1;
            break;
        }
    }
    df_settle_memop_prov(d, tlo, thi);
}

/*
 * CP4 -- gvec operand notes.
 *
 * See insn_dataflow_note_gvec() in the header for why these exist.  A note is
 * anchored to the last op the constructor had emitted when it was made, so
 * the instruction walk can attribute it without any op numbering: the note
 * belongs to whichever instruction's op range contains its anchor.
 *
 * Overflow is recorded, not silently dropped -- a vector operand we failed to
 * note is a missing dependency, which is the direction that costs a consumer
 * correctness rather than accuracy.
 */
void insn_dataflow_note_gvec(uint32_t dofs, uint32_t aofs, uint32_t bofs,
                             uint32_t oprsz)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_gvec >= DF_MAX_GVEC_NOTES) {
        df_gvec_overflow = true;
        return;
    }
    df_gvec[df_n_gvec].anchor = QTAILQ_LAST(&tcg_ctx->ops);
    df_gvec[df_n_gvec].dofs = dofs;
    df_gvec[df_n_gvec].aofs = aofs;
    df_gvec[df_n_gvec].bofs = bofs;
    df_gvec[df_n_gvec].oprsz = oprsz;
    df_n_gvec++;
}

/* Fold every note anchored inside [first, end) into this instruction. */
static void df_apply_gvec_notes(InsnDataflow *d, TCGOp *first, TCGOp *end)
{
    TCGOp *op;

    if (df_n_gvec == 0) {
        return;
    }
    for (op = first; op != end; op = QTAILQ_NEXT(op, link)) {
        for (unsigned i = 0; i < df_n_gvec; i++) {
            if (df_gvec[i].anchor != op) {
                continue;
            }
            /*
             * Both source operands are read and the destination written,
             * whether or not the constructor folded them away.  aofs == bofs
             * is the folded case and df_add_field() merges the two into one
             * field, which is right: it is one register, read once.
             */
            df_add_field(d, df_gvec[i].aofs, df_gvec[i].oprsz,
                         INSN_DF_RD, NULL);
            df_add_field(d, df_gvec[i].bofs, df_gvec[i].oprsz,
                         INSN_DF_RD, NULL);
            df_add_field(d, df_gvec[i].dofs, df_gvec[i].oprsz,
                         INSN_DF_WR, NULL);
        }
        if (op == end) {
            break;
        }
    }
}

/*
 * CP-M -- memop notes.  See insn_dataflow_note_memop() in the header.
 *
 * The emitter tells us which temp is the DATA and which is the ADDRESS,
 * because they are separate parameters of tcg_gen_qemu_ld/st_*.  A post-hoc
 * walk cannot recover that: qemu_ld_i64 has the address temp as its only
 * input, so the loaded value's provenance comes out as the address
 * registers.
 */
void insn_dataflow_note_memop(const void *val_ts, unsigned nval,
                              const void *addr_ts,
                              unsigned size, bool is_store)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_memop >= DF_MAX_MEMOP_NOTES) {
        df_memop_overflow = true;
        return;
    }
    df_memop[df_n_memop].anchor = QTAILQ_LAST(&tcg_ctx->ops);
    df_memop[df_n_memop].val_ts = val_ts;
    df_memop[df_n_memop].nval = nval;
    df_memop[df_n_memop].addr_ts = addr_ts;
    df_memop[df_n_memop].size = size;
    df_memop[df_n_memop].is_store = is_store;
    df_memop[df_n_memop].rec = -1;
    df_memop[df_n_memop].alias_n = df_n_alias;
    df_memop[df_n_memop].alias_dropped = df_alias_overflow;
    df_memop[df_n_memop].zero_n = df_n_zero;
    df_memop[df_n_memop].zero_dropped = df_zero_overflow;
    df_memop[df_n_memop].fold_n = df_n_fold;
    df_memop[df_n_memop].fold_dropped = df_fold_overflow;
    /*
     * Inside an alternate-path scope this emission mirrors the note @alt_mark
     * positions in; outside one it is an access of its own.  A mirror of a
     * note that does not exist stays -1 and the access is allocated
     * normally: an unmatched alternate is REPORTED, never dropped.
     */
    df_memop[df_n_memop].alt_of = -1;
    if (df_alt_open) {
        unsigned src = df_alt_mark + df_alt_taken;

        df_alt_taken++;
        if (src < df_n_memop) {
            df_memop[df_n_memop].alt_of = (int)src;
        }
    }
    df_n_memop++;
}

/*
 * The alternate-path scope.  See insn_dataflow_note_path_alt() in the header
 * for what it states and why only the emitter can state it.
 */
unsigned insn_dataflow_memop_mark(void)
{
    if (df_disabled()) {
        return 0;
    }
    df_bind();
    return df_n_memop;
}

void insn_dataflow_note_path_alt(unsigned mark)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    df_alt_open = true;
    df_alt_mark = mark;
    df_alt_taken = 0;
}

void insn_dataflow_note_path_alt_end(void)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    df_alt_open = false;
    df_alt_taken = 0;
}

/*
 * CP-M, the zero-register half.  See insn_dataflow_note_zero_reg() in the
 * header for why the note is taken at the accessor and not at the access.
 *
 * The list is append-only for the translation and is searched by temp
 * identity within a window of notes.  On two of the three targets the
 * accessor returns a FRESH temp, so identity is exact; on RISC-V it returns
 * ctx->zero, which is tcg_constant_tl(0) and therefore the same temp every
 * constant zero in the block resolves to -- which is why the note carries the
 * op the emitter had last produced when it was taken.  See DfZeroNote: the
 * anchor is what lets a register WRITE be resolved against the notes of its
 * OWN instruction, and without it the shared constant would carry one
 * instruction's zero register into every write after it.
 *
 * The anchor is taken unconditionally, including for a constant temp.  The
 * folded-register notes leave it NULL there, because a constant is interned
 * by value and no op can redefine it, so a note about one cannot go stale.
 * That reasoning is about STALENESS and does not transfer: here the anchor is
 * not guarding against a later write to the temp, it is recording WHICH
 * INSTRUCTION said the word, and a constant temp is exactly the case where
 * two instructions can say it about the same temp.
 */
/*
 * CP-M, the preserve-read half.  See insn_dataflow_note_preserve_read() in
 * the header for why the note is taken at the WRITEBACK and nowhere else.
 *
 * The op is looked up rather than passed because the emitter has just
 * produced it: `tcg_gen_deposit_tl(...)` then this call, exactly as the
 * folded-register notes are taken.  Deduplicated against the newest note on
 * the pair, for DfZeroNote's reason -- one emitter may state the same fact
 * twice and two emitters may state different facts about one temp.
 */
void insn_dataflow_note_preserve_read(const void *ts, const void *mark)
{
    const TCGOp *op;

    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_preserve >= DF_MAX_PRESERVE_NOTES) {
        /*
         * No flag reaches a consumer for this one, and none should: a lost
         * preserve-note leaves the read looking like an operand, which
         * publishes an edge the instruction does not need.  That is
         * pessimism, the direction this file errs in on purpose, and not the
         * missing-source direction the other notes' overflow flags exist to
         * report.
         */
        df_preserve_overflow = true;
        return;
    }
    op = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_preserve; i-- > 0; ) {
        if (df_preserve[i].ts == ts && df_preserve[i].end == op) {
            return;
        }
        break;
    }
    df_preserve[df_n_preserve].ts = ts;
    df_preserve[df_n_preserve].mark = mark;
    df_preserve[df_n_preserve].end = op;
    df_n_preserve++;
}

/*
 * The supplied-value half.  See insn_dataflow_note_supplied_value() in the
 * header for the one shape it exists for, and for why its absence is the
 * dangerous direction rather than the safe one.
 */
void insn_dataflow_note_supplied_value(const void *ts, const void *mark)
{
    const TCGOp *op;

    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_value >= DF_MAX_VALUE_NOTES) {
        df_value_overflow = true;
        return;
    }
    op = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_value; i-- > 0; ) {
        if (df_value[i].ts == ts && df_value[i].end == op) {
            return;
        }
        break;
    }
    df_value[df_n_value].ts = ts;
    df_value[df_n_value].mark = mark;
    df_value[df_n_value].end = op;
    df_n_value++;
}

/*
 * THE REPRESENTATION CARRIERS.  See insn_dataflow_note_repr_carrier() in the
 * header for what one is and why the emitter has to say so.
 *
 * A per-translation note and not a target-init declaration, unlike the
 * selectors beside it: a carrier is a TEMP, so it is created afresh for every
 * translation block and the pointer that identifies it is only good for that
 * one.  tcg_func_start() clears the note array before translator_loop() calls
 * init_disas_context(), which is where a target states this, so the note is in
 * place before the first op of the block exists.
 *
 * @stands_for_ts is resolved to its GLOBAL INDEX here rather than kept as a
 * pointer, because the index is what the read set and the provenance are
 * written in and this is the one place that has to do the lookup.
 */
void insn_dataflow_note_repr_carrier(const void *ts, const void *stands_for_ts)
{
    const TCGTemp *g = stands_for_ts;
    unsigned idx;

    if (df_disabled()) {
        return;
    }
    /*
     * Both halves have to be real and the second has to be a global: the
     * note's whole content is "read this as THAT register", and a name that
     * does not resolve would silently turn the fold into a dropped read.
     */
    if (ts == NULL || g == NULL || g->kind != TEMP_GLOBAL) {
        return;
    }
    df_bind();
    idx = (unsigned)(g - tcg_ctx->temps);
    if (idx >= (unsigned)tcg_ctx->nb_globals) {
        return;
    }
    for (unsigned i = 0; i < df_n_carrier; i++) {
        if (df_carrier[i].ts == ts) {
            return;                 /* the same declaration twice */
        }
    }
    if (df_n_carrier >= DF_MAX_CARRIER_NOTES) {
        return;
    }
    df_carrier[df_n_carrier].ts = ts;
    df_carrier[df_n_carrier].stands_for = idx;
    df_carrier[df_n_carrier].defined_here = false;
    df_n_carrier++;
}

/*
 * The op an emitter has produced so far, as an opaque handle.
 *
 * Paired with insn_dataflow_note_preserve_read(): taken BEFORE the writeback
 * is emitted, it bounds the note to the ops that writeback produced and to no
 * others.  NULL is a legitimate answer -- the emitter may be the first thing
 * in the block -- and the note reads it as "from the beginning".
 */
const void *insn_dataflow_mark(void)
{
    if (df_disabled()) {
        return NULL;
    }
    return QTAILQ_LAST(&tcg_ctx->ops);
}

void insn_dataflow_note_zero_reg(const void *ts)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_zero >= DF_MAX_ZERO_NOTES) {
        df_zero_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    /*
     * Deduplicated against the NEWEST note only, and on the PAIR.  The RISC-V
     * accessor returns one shared temp, so an undeduplicated list would fill
     * with copies of it and then overflow, turning a fact the extractor holds
     * into a refusal it does not need -- but deduplicating on the temp ALONE,
     * which is what this did until the anchor existed, collapses every
     * instruction's statement into the first one's and leaves the write path
     * with a single block-wide note it cannot attribute to anybody.
     *
     * Newest-first rather than any-match, for DfFoldNote's reason: the same
     * temp restated under a different anchor is a different fact.
     */
    for (unsigned i = df_n_zero; i-- > 0; ) {
        if (df_zero[i].ts == ts && df_zero[i].anchor == anchor) {
            return;
        }
        break;
    }
    df_zero[df_n_zero].ts = ts;
    df_zero[df_n_zero].anchor = anchor;
    df_n_zero++;
}

/*
 * CP-M, the discarded-write half.  See insn_dataflow_note_discarded_write()
 * in the header for what the note says and why the name rather than an index.
 *
 * Same list discipline as the zero-register notes -- append-only for the
 * translation, deduplicated on the (temp, register, anchor) TRIPLE, resolved
 * only inside the instruction whose op range reached the anchor.  The
 * register is part of the key because one temp legitimately stands for two
 * discarded destinations: MIPS `mul` destroys HI and LO together and states
 * both against the multiply's own result temp.
 */
static void df_note_discard(const void *ts, const char *reg, bool zero,
                            bool holder, bool by_index)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    if (ts == NULL || (reg == NULL && !zero)) {
        return;
    }
    df_bind();
    if (df_n_discard >= DF_MAX_DISCARD_NOTES) {
        df_discard_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_discard; i-- > 0; ) {
        if (df_discard[i].ts == ts && df_discard[i].reg == reg &&
            df_discard[i].zero == zero && df_discard[i].holder == holder &&
            df_discard[i].by_index == by_index &&
            df_discard[i].anchor == anchor) {
            return;                 /* the same statement twice */
        }
        break;
    }
    df_discard[df_n_discard].ts = ts;
    df_discard[df_n_discard].reg = reg;
    df_discard[df_n_discard].zero = zero;
    df_discard[df_n_discard].holder = holder;
    df_discard[df_n_discard].by_index = by_index;
    df_discard[df_n_discard].anchor = anchor;
    df_n_discard++;
}

void insn_dataflow_note_discarded_write(const void *ts, const char *reg)
{
    df_note_discard(ts, reg, false, false, false);
}

void insn_dataflow_note_discarded_zero_write(const void *ts)
{
    df_note_discard(ts, NULL, true, false, false);
}

void insn_dataflow_note_zero_write_holder(const void *ts)
{
    df_note_discard(ts, NULL, true, true, false);
}

/*
 * CP-M, the INDEXED-WRITE half.  See insn_dataflow_note_indexed_write() in
 * the header for why a performed write arrives on the same list as a
 * discarded one, and why it is nevertheless not the same statement.
 *
 * It shares df_note_discard()'s storage because it needs exactly what that
 * list provides and nothing else: a register named in the target's own
 * namespace, a temp whose end-of-instruction provenance is the answer, and
 * the anchor that keeps a block of them apart.  @by_index is what separates
 * the two facts once they are there.
 */
void insn_dataflow_note_indexed_write(const void *ts, const char *reg)
{
    df_note_discard(ts, reg, false, false, true);
}

/*
 * CP-M, the encoded-immediate half.  See insn_dataflow_note_encoded_imm() in
 * the header for why the note is taken at the decoder and nowhere below it.
 *
 * Same list discipline as the zero-register notes -- append-only for the
 * translation, searched by temp identity inside the window of notes this
 * instruction took, deduplicated on the (temp, anchor) PAIR.  The pair is
 * what makes `andi a0,a1,8` and `slli a2,a3,8` two facts rather than one:
 * tcg_constant_tl(8) is one temp and each instruction states it about
 * itself.  Deduplicating on the temp alone would collapse them into the
 * first, which is the bug the zero-register notes had before the anchor
 * existed.
 *
 * The anchor is taken unconditionally, including for a constant temp, for
 * the reason insn_dataflow_note_zero_reg() gives at length: the anchor here
 * is not guarding against a later write to the temp, it is recording WHICH
 * INSTRUCTION said the word, and an interned constant is precisely the case
 * where two instructions say it about the same temp.
 */
void insn_dataflow_note_encoded_imm(const void *ts)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_imm >= DF_MAX_IMM_NOTES) {
        df_imm_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_imm; i-- > 0; ) {
        if (df_imm[i].ts == ts && df_imm[i].anchor == anchor) {
            return;
        }
        break;
    }
    df_imm[df_n_imm].ts = ts;
    df_imm[df_n_imm].anchor = anchor;
    df_imm[df_n_imm].value = 0;
    df_imm[df_n_imm].role = 0;
    df_n_imm++;
}

/*
 * CP-M, the encoded-immediate half -- the VALUE-STATING form (#252).  See
 * insn_dataflow_note_encoded_imm_value() in the header for what the two
 * roles mean and why the anchor means something different for each.
 *
 * Same list, same cap and same overflow behaviour as the temp form, because
 * it answers the same question about the same field and a consumer reading
 * @imm_stated must not be able to tell which call said it.
 *
 * The dedup key is the whole note -- (anchor, role, value) -- and it is a
 * FULL scan of this translation's notes rather than the temp form's
 * look-at-the-last-one.  An OPERAND emitter states one field per op it
 * anchors to and so can never collide; a NON_DATAFLOW emitter states its
 * field once and its anchor is whatever op happened to be last, which on
 * `teq rs,rt,code` with rs == rt is the PREVIOUS instruction's op -- the
 * degenerate always-trap path emits nothing before the note.  Scoping keeps
 * that note out of this instruction (it is consumed at the boundary, so it
 * never enters the window), and the full-scan dedup keeps a repeated
 * statement from consuming the cap.
 */
void insn_dataflow_note_encoded_imm_value(uint64_t value, unsigned role)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    if (role != INSN_DF_IMM_ROLE_OPERAND &&
        role != INSN_DF_IMM_ROLE_NON_DATAFLOW) {
        /*
         * A role this file does not know is a caller that has not been
         * updated, and inventing a meaning for it is how a fabricated fact
         * gets onto the wire.  Dropped, and the instruction reports
         * imm_stated = 0, which is the state every consumer refuses on.
         */
        return;
    }
    df_bind();
    if (df_n_imm >= DF_MAX_IMM_NOTES) {
        df_imm_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = 0; i < df_n_imm; i++) {
        if (df_imm[i].ts == NULL && df_imm[i].anchor == anchor &&
            df_imm[i].role == role && df_imm[i].value == value) {
            return;
        }
    }
    df_imm[df_n_imm].ts = NULL;
    df_imm[df_n_imm].anchor = anchor;
    df_imm[df_n_imm].value = value;
    df_imm[df_n_imm].role = (uint8_t)role;
    df_n_imm++;
}

/*
 * CP-M, the folded-register half.  See insn_dataflow_note_folded_reg() in the
 * header for why the note is taken at the accessor and not at the access.
 *
 * Same list discipline as the zero notes -- append-only for the translation,
 * searched by temp identity, scoped to the notes taken before the access
 * being resolved -- and the same shared-constant caveat, bounded here by a
 * property of the one emitter that states a note.  Without CF_PCREL
 * eip_next_tl() returns tcg_constant_tl(s->pc), which is interned, so a
 * SECOND way to reach the same temp would be a store whose data operand is
 * the identical interned constant.  x86 does not have one: an immediate
 * operand is materialised with tcg_gen_movi_tl() into a temp of its own
 * (target/i386/tcg/emit.c.inc, X86_OP_IMM), never handed to a store emitter
 * as the shared constant.  The claim is also measured rather than left as an
 * argument -- the plugin's Capstone shadow scores every published row, and a
 * store that acquired REG_PC without being a call would appear there.
 */
void insn_dataflow_note_folded_reg(const void *ts, const void *src_ts)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_fold >= DF_MAX_FOLD_NOTES) {
        df_fold_overflow = true;
        return;
    }
    /*
     * A constant temp is interned by value and no op defines it, so there is
     * nothing that could make the note stale and no anchor to take.  Any
     * other temp is anchored to the op that has just written it -- the note
     * is being taken by the emitter that produced the value, so the tail of
     * the op list IS that write.
     */
    const TCGOp *anchor = ((const TCGTemp *)ts)->kind == TEMP_CONST
                          ? NULL : QTAILQ_LAST(&tcg_ctx->ops);

    /*
     * Deduplicated against the NEWEST note for this temp, because a block
     * that calls the same target twice resolves the same interned constant
     * twice and an undeduplicated list would fill with copies and then
     * overflow, turning a fact the extractor holds into a refusal it does
     * not need.  Newest-first rather than any-match: the same temp restated
     * after a different write is a different fact, and an any-match scan
     * would drop the restatement and leave the stale note newest.
     */
    for (unsigned i = df_n_fold; i-- > 0; ) {
        if (df_fold[i].ts != ts) {
            continue;
        }
        if (df_fold[i].src_ts == src_ts && df_fold[i].anchor == anchor) {
            return;
        }
        break;
    }
    df_fold[df_n_fold].ts = ts;
    df_fold[df_n_fold].src_ts = src_ts;
    df_fold[df_n_fold].anchor = anchor;
    df_n_fold++;
}

/*
 * CP-M, the folded-READ half.  See insn_dataflow_note_folded_read() in the
 * header for what the note says and why it needs no temp.
 *
 * Same list discipline as the zero-register notes -- append-only for the
 * translation, anchored to the op the stating emitter had produced, resolved
 * only inside the instruction whose op range reached that anchor.
 *
 * Deduplicated against the NEWEST note only, and on the (register, kind,
 * anchor) triple.  One instruction can state the same register twice -- a call
 * states it for the pushed return address and again for the target -- and both
 * are one fact; the same register restated under a LATER anchor is a different
 * instruction's fact and must not be swallowed.
 */
static void df_note_encread(const void *src_ts, bool zero)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    if (src_ts == NULL && !zero) {
        return;
    }
    df_bind();
    if (df_n_encread >= DF_MAX_ENCREAD_NOTES) {
        df_encread_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_encread; i-- > 0; ) {
        if (df_encread[i].env_size == 0 &&
            df_encread[i].src_ts == src_ts &&
            df_encread[i].zero == (zero ? 1 : 0) &&
            df_encread[i].anchor == anchor) {
            return;
        }
        break;
    }
    df_encread[df_n_encread].src_ts = src_ts;
    df_encread[df_n_encread].anchor = anchor;
    df_encread[df_n_encread].zero = zero ? 1 : 0;
    df_encread[df_n_encread].env_off = 0;
    df_encread[df_n_encread].env_size = 0;
    df_encread[df_n_encread].name = NULL;
    df_n_encread++;
}

void insn_dataflow_note_folded_read(const void *src_ts)
{
    df_note_encread(src_ts, false);
}

void insn_dataflow_note_folded_read_zero(void)
{
    df_note_encread(NULL, true);
}

/*
 * The THIRD folded-read form: a register the instruction reads that the
 * emulator resolved BEFORE the op stream existed.  See
 * insn_dataflow_note_stated_read_env() in the header for what the note says.
 *
 * It shares df_encread[]'s storage and therefore its cursor discipline, which
 * is the whole reason it lives here rather than on a list of its own: the
 * anchor window that keeps one instruction's folded reads apart from the next
 * one's is exactly the window this note needs, and a second list would be a
 * second chance to get that wrong.  The pair (range, anchor) is the key --
 * one instruction stating the same gate twice is one fact, two instructions
 * stating it are two.
 */
void insn_dataflow_note_stated_read_env(uint32_t off, uint32_t size)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    if (size == 0) {
        /*
         * An unbounded range cannot be told from the temp forms in this
         * struct and would be indistinguishable from "no note" downstream.
         * Refused at the door rather than stored as a fact nobody can read.
         */
        return;
    }
    df_bind();
    if (df_n_encread >= DF_MAX_ENCREAD_NOTES) {
        df_encread_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_encread; i-- > 0; ) {
        if (df_encread[i].env_size == size &&
            df_encread[i].env_off == off &&
            df_encread[i].anchor == anchor) {
            return;
        }
        break;
    }
    df_encread[df_n_encread].src_ts = NULL;
    df_encread[df_n_encread].anchor = anchor;
    df_encread[df_n_encread].zero = 0;
    df_encread[df_n_encread].env_off = off;
    df_encread[df_n_encread].env_size = size;
    df_encread[df_n_encread].name = NULL;
    df_n_encread++;
}

/*
 * The FOURTH folded-read form: a register stated by NAME.  See
 * insn_dataflow_note_stated_read_name() in the header for what it says and
 * why a name rather than a range.
 *
 * It shares df_encread[]'s storage for the reason the range form does: the
 * per-instruction cursor window that keeps one decoder's statements apart
 * from the next one's already exists here, and a fourth list would be a
 * fourth chance to get that window wrong.  The key is (name, anchor) -- one
 * instruction naming the same register twice is one fact.
 */
void insn_dataflow_note_stated_read_name(const char *reg)
{
    const TCGOp *anchor;

    if (df_disabled()) {
        return;
    }
    if (reg == NULL || reg[0] == '\0') {
        /*
         * An unnamed member is indistinguishable from "no note" downstream,
         * and a row with an empty name would put a nameless register into a
         * consumer's name-to-register map.  Refused at the door.
         */
        return;
    }
    df_bind();
    if (df_n_encread >= DF_MAX_ENCREAD_NOTES) {
        df_encread_overflow = true;
        return;
    }
    anchor = QTAILQ_LAST(&tcg_ctx->ops);
    for (unsigned i = df_n_encread; i-- > 0; ) {
        if (df_encread[i].name != NULL &&
            df_encread[i].anchor == anchor &&
            strcmp(df_encread[i].name, reg) == 0) {
            return;
        }
        break;
    }
    df_encread[df_n_encread].src_ts = NULL;
    df_encread[df_n_encread].anchor = anchor;
    df_encread[df_n_encread].zero = 0;
    df_encread[df_n_encread].env_off = 0;
    df_encread[df_n_encread].env_size = 0;
    df_encread[df_n_encread].name = reg;
    df_n_encread++;
}

/* CP-M, the address half.  See insn_dataflow_note_addr_alias() in the header. */
void insn_dataflow_note_addr_alias(const void *alias_ts, const void *real_ts)
{
    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_alias >= DF_MAX_ALIAS_NOTES) {
        df_alias_overflow = true;
        return;
    }
    df_alias[df_n_alias].alias_ts = alias_ts;
    df_alias[df_n_alias].real_ts = real_ts;
    df_n_alias++;
}

/*
 * CP-H -- the per-helper usage table.
 *
 * The argument list gives operand IDENTITY.  It does not give USAGE: nothing
 * in TCGHelperInfo says whether helper H reads through its third argument,
 * writes through it, or both.  That is a STATIC PER-HELPER FACT -- bounded,
 * enumerable, and written down here once rather than rediscovered at runtime.
 *
 * Two rules govern this table and they are not negotiable:
 *
 *   1. A row is a CLAIM ABOUT QEMU SOURCE and carries where it was read from.
 *      A row whose justification is "it looks like an accumulate" is the
 *      false-justification class this project has a standing memory entry
 *      about, and is worse than no row: an absent row costs precision, a
 *      wrong row costs correctness.
 *   2. Absence is not "read-only".  A (helper, argument) pair with no row is
 *      recorded as read-and-written and the instruction is labelled
 *      INSN_DF_HELPER_APPROX, so a consumer can see the over-approximation
 *      instead of inheriting it as fact.
 *
 * @argno is the LOGICAL argument index -- the helper's own parameter
 * position, counting from zero and counting tcg_env if the helper takes it.
 */
#if defined(TARGET_I386)
#include "insn-dataflow-usage/i386.c.inc"
#elif defined(TARGET_ARM)
#include "insn-dataflow-usage/arm.c.inc"
#elif defined(TARGET_RISCV)
#include "insn-dataflow-usage/riscv.c.inc"
#elif defined(TARGET_MIPS)
#include "insn-dataflow-usage/mips.c.inc"
#else
/*
 * No table for this target yet.  Not a defect and not a silent default: with
 * no row every helper stays INSN_DF_HELPER_OPAQUE, which is exactly what the
 * whole tree did before any table existed, and the label says so on every
 * instruction that reaches one.
 */
static const DfHelperUsage df_helper_usage[] = {
    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }
};
#endif

/*
 * QEMU_DF_NO_USAGE_TABLE makes every lookup miss.  The A/B for this table has
 * to be ONE BINARY: the workload is not bit-deterministic across processes --
 * two runs of the same bench differ by hundreds of instructions -- so a
 * before/after taken from two builds compares two different runs and any
 * movement it shows is unattributable.  Measured: the first A/B moved
 * aarch64's irdf disagreements by 19 and its agreements by 63 with the
 * denominator itself moving, which is not a result.
 */
static bool df_notable, df_notable_read;

static bool df_table_off(void)
{
    if (!df_notable_read) {
        const char *e = getenv("QEMU_DF_NO_USAGE_TABLE");

        df_notable_read = true;
        df_notable = e && atoi(e) != 0;
    }
    return df_notable;
}

static const DfHelperUsage *df_helper_usage_row(const char *name)
{
    if (df_table_off()) {
        return NULL;
    }
    for (const DfHelperUsage *u = df_helper_usage; u->name; u++) {
        if (!strcmp(u->name, name)) {
            return u;
        }
    }
    return NULL;
}

static bool df_helper_usage_of(const char *name, unsigned argno, uint8_t *dir)
{
    const DfHelperUsage *u = df_helper_usage_row(name);

    if (u && argno < DF_MAX_HELPER_ARGS && u->argdir[argno]) {
        *dir = u->argdir[argno];
        return true;
    }
    return false;
}

/* The extent the row states for pointer argument @argno, or 0. */
static uint32_t df_helper_argsize(const DfHelperUsage *u, unsigned argno)
{
    if (u && argno < DF_MAX_HELPER_ARGS) {
        return u->argsize[argno];
    }
    return 0;
}

/*
 * CP-H -- helper notes.  See insn_dataflow_note_helper() in the header.
 */
void insn_dataflow_note_helper(const void *call_op, const void *info_p,
                               const void *ret_ts, const void *const *args)
{
    const TCGHelperInfo *info = info_p;
    DfHelperNote *n;
    unsigned nargs = 0;

    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_helper >= DF_MAX_HELPER_NOTES) {
        df_helper_overflow = true;
        return;
    }
    n = &df_helper[df_n_helper];
    memset(n, 0, sizeof(*n));
    n->anchor = call_op;
    n->name = info->name;
    n->flags = info->flags;

    /*
     * How many LOGICAL arguments there are is not stored: info->nr_in counts
     * physical slots, which is larger for i128 and unchanged for the extension
     * temps.  in[].arg_idx maps each slot back to the parameter it came from,
     * so the largest of those plus one is the count -- and it is exact rather
     * than parsed out of the typemask, which stops at the first void field and
     * cannot distinguish "no more arguments" from a void one.
     */
    for (unsigned i = 0; i < info->nr_in; i++) {
        if (info->in[i].arg_idx + 1u > nargs) {
            nargs = info->in[i].arg_idx + 1u;
        }
    }
    if (nargs > DF_MAX_HELPER_ARGS) {
        nargs = DF_MAX_HELPER_ARGS;
        n->args_overflow = true;
    }
    for (unsigned k = 0; k < nargs; k++) {
        /*
         * Slot 0 of the typemask is the RETURN type, so parameter k is at
         * slot k + 1 -- three bits each, dh_typecode_* in helper-head.h.inc.
         */
        n->typecode[k] = (info->typemask >> ((k + 1) * 3)) & 7;
        n->arg[k] = args ? (const TCGTemp *)args[k] : NULL;
    }
    n->nargs = nargs;
    (void)ret_ts;
    df_n_helper++;
}

/*
 * CP-H, the vector half.  Attaches to the call the constructor has just
 * emitted, which is the note taken a moment ago by tcg_gen_callN.
 */
void insn_dataflow_note_gvec_ool(const uint32_t *off, const uint8_t *dir,
                                 unsigned n, uint32_t oprsz)
{
    const TCGOp *last;
    DfHelperNote *h;

    if (df_disabled()) {
        return;
    }
    df_bind();
    if (df_n_helper == 0 || n > INSN_DF_MAX_GVEC_OPERANDS) {
        /*
         * No note to attach to: the helper note array overflowed, or the
         * constructor gained an operand this code does not carry.  Either way
         * the call keeps the unrefined treatment and says so, rather than
         * being described by roles that were never recorded.
         */
        df_helper_overflow = true;
        return;
    }
    last = QTAILQ_LAST(&tcg_ctx->ops);
    h = &df_helper[df_n_helper - 1];
    if (h->anchor != last) {
        /*
         * The constructor's helper is not the last op emitted.  That should
         * not happen -- fn() emits the call and nothing after it -- and if it
         * ever does, attaching the roles to the wrong call would describe one
         * instruction with another's operands.
         */
        df_helper_overflow = true;
        return;
    }
    h->has_gvec = true;
    h->gvec_n = n;
    h->gvec_oprsz = oprsz;
    for (unsigned i = 0; i < n; i++) {
        h->gvec_off[i] = off[i];
        h->gvec_dir[i] = dir[i];
    }
}

static const DfHelperNote *df_find_helper(const TCGOp *op)
{
    for (unsigned i = 0; i < df_n_helper; i++) {
        if (df_helper[i].anchor == op) {
            return &df_helper[i];
        }
    }
    return NULL;
}

void insn_dataflow_extract(unsigned num_insns)
{
    TCGContext *s = tcg_ctx;
    TCGOp *op, *first = NULL;
    const TCGOp *marker = NULL;
    unsigned idx = 0;
    unsigned memop_cursor;
    unsigned zero_cursor;
    unsigned imm_cursor;
    unsigned disc_cursor;
    unsigned encread_cursor;
    bool prof;
    int64_t t0;

    if (df_disabled()) {
        if (df) {
            df_ninsns = 0;
        }
        return;
    }
    df_bind();
    prof = df_profiling();
    t0 = prof ? df_now() : 0;

    df_gen++;
    df_nslots = 0;
    df_slots_overflow = false;
    df_ninsns = 0;
    if (num_insns > INSN_DF_MAX_INSNS) {
        num_insns = INSN_DF_MAX_INSNS;
    }
    memset(df_out, 0, num_insns * sizeof(df_out[0]));

    /*
     * One cursor for the whole block: the notes were made in emission order,
     * the instructions are walked in that same order, and a memop op is
     * matched to the note whose anchor range it falls in.  A local rather
     * than file scope because it belongs to this translation, and a
     * translation belongs to one context.
     */
    memop_cursor = 0;
    zero_cursor = 0;
    imm_cursor = 0;
    disc_cursor = 0;
    encread_cursor = 0;

    QTAILQ_FOREACH(op, &s->ops, link) {
        if (op->opc != INDEX_op_insn_start) {
            continue;
        }
        if (first != NULL && idx > 0) {
            df_insn(&df_out[idx - 1], first, op, marker, &memop_cursor,
                    &zero_cursor, &imm_cursor, &disc_cursor,
                    &encread_cursor);
            df_apply_gvec_notes(&df_out[idx - 1], first, op);
        }
        if (idx >= num_insns) {
            first = NULL;
            break;
        }
        idx++;
        /*
         * The op that OPENS this instruction, kept because an emitter states
         * a zero-register note before the instruction has emitted an op of
         * its own and the note then anchors here.  See df_insn().
         */
        marker = op;
        first = QTAILQ_NEXT(op, link);
    }
    if (first != NULL && idx > 0) {
        df_insn(&df_out[idx - 1], first, NULL, marker, &memop_cursor,
                &zero_cursor, &imm_cursor, &disc_cursor,
                &encread_cursor);
        df_apply_gvec_notes(&df_out[idx - 1], first, NULL);
    }
    df_ninsns = idx;

    if (df_dumping()) {
        unsigned k = 0;

        QTAILQ_FOREACH(op, &s->ops, link) {
            if (op->opc != INDEX_op_insn_start || k >= df_ninsns) {
                continue;
            }
            df_emit(tcg_get_insn_start_param(op, 0), &df_out[k]);
            k++;
        }
    }

    /*
     * The notes belonged to this translation only.  Reset after consuming so
     * a stale anchor from a previous TB can never be matched against a
     * recycled TCGOp address in the next one.
     */
    if (df_gvec_overflow) {
        /* Same direction as fields_overflow: say so rather than lose it. */
        for (unsigned i = 0; i < df_ninsns; i++) {
            df_out[i].fields_overflow = 1;
        }
    }
    if (df_memop_overflow) {
        /*
         * The block ran out of note slots, so somewhere past that point an
         * access has no note and the memop records are short.  Which
         * instruction it was is not recoverable here, so every instruction
         * in the block is marked: an over-broad refusal, never a quiet
         * partial answer.
         */
        for (unsigned i = 0; i < df_ninsns; i++) {
            df_out[i].memops_overflow = 1;
        }
    }
    df_n_gvec = 0;
    df_gvec_overflow = false;
    df_n_memop = 0;
    df_memop_overflow = false;
    df_alt_open = false;
    df_alt_mark = 0;
    df_alt_taken = 0;
    df_n_alias = 0;
    df_alias_overflow = false;
    if (df_helper_overflow) {
        /*
         * A call whose operand set was never recorded is a call described by
         * the fallback, and the fallback is the thing CP-H exists to replace.
         * Say so on every instruction of the block rather than let one that
         * happens to be exact claim it.
         */
        for (unsigned i = 0; i < df_ninsns; i++) {
            if (df_out[i].helper_model < INSN_DF_HELPER_OPAQUE &&
                df_out[i].n_calls) {
                df_out[i].helper_model = INSN_DF_HELPER_OPAQUE;
            }
        }
    }
    df_n_helper = 0;
    df_helper_overflow = false;

    if (prof) {
        df_prof_ns += df_now() - t0;
        df_prof_tbs++;
        df_prof_insns += idx;
        QTAILQ_FOREACH(op, &s->ops, link) {
            df_prof_ops++;
        }
        if (df_prof_tbs % df_prof_every == 0) {
            df_prof_dump();
        }
    }
}

/*
 * The three read-side entry points below are the ones a plugin can reach.  A
 * NULL scratch means this context has never run an extraction -- extraction
 * disabled, or a caller arriving before the first translation -- and each
 * answers as it would for an extraction that recorded nothing, which is the
 * pessimistic direction the rest of this file also takes.
 */
const InsnDataflow *insn_dataflow_get(unsigned i)
{
    return df && i < df_ninsns ? &df_out[i] : NULL;
}

/* Map a provenance bit at or above nregs back to the env offset it interned. */
uint32_t insn_dataflow_prov_field(unsigned bit, bool *valid)
{
    unsigned base = tcg_ctx->nb_globals;

    if (!df || bit < base || bit - base >= df_nslots) {
        *valid = false;
        return 0;
    }
    *valid = true;
    return df_slot_off[bit - base];
}

/*
 * Did provenance lose a field to slot exhaustion during this translation?
 *
 * Reported per TB rather than per instruction because that is the truth: the
 * slot table is interned for the block.  A consumer told "incomplete" for one
 * instruction when the exhaustion happened in another is being told something
 * pessimistic, which is the direction this code errs in everywhere else.
 */
/*
 * Is @bit one of the load-data bits, and if so which of this instruction's
 * accesses does it stand for?
 *
 * The caller still has to hold the memop records to make anything of the
 * slot number, which is deliberate: a bit that resolves to an access the
 * caller has not looked at is a bit it cannot attribute, and attributing it
 * to a register instead is the mistake this whole region exists to prevent.
 */
bool insn_dataflow_prov_memop(unsigned bit, unsigned *slot)
{
    if (bit < INSN_DF_MEMOP_PROV_BASE || bit >= INSN_DF_MAX_REGS) {
        return false;
    }
    if (slot) {
        *slot = bit - INSN_DF_MEMOP_PROV_BASE;
    }
    return true;
}

bool insn_dataflow_prov_truncated(void)
{
    /*
     * Block-wide, and deliberately over-broad: both flags say a provenance
     * somewhere in this translation is missing a member it should carry, and
     * neither can say which instruction.  An over-broad refusal is the
     * direction that costs a consumer precision; a per-instruction guess
     * would cost it a dependency.
     *
     * @df_zero_overflow is the zero-register notes' cap.  A write whose
     * source operand was the architectural zero register would arrive with an
     * empty provenance, which for a destination reads as "the value is a
     * constant" -- exactly the claim that cannot be supported once a note has
     * been dropped.
     *
     * @df_discard_overflow is the discarded-write notes' cap, and it is here
     * for the sharper version of the same reason: a dropped note is a
     * DESTINATION missing from the list, and a consumer whose list is QEMU's
     * would publish a shorter set than the instruction writes.
     */
    return df && (df_slots_overflow || df_zero_overflow ||
                  df_discard_overflow);
}

/*
 * THE REGISTER FILES A TARGET DECLARED.
 *
 * Process-wide and write-once: the layout of CPUArchState is a property of
 * the build, not of a translation or a vCPU, so this is filled in when the
 * target creates its TCG globals and read from every thread thereafter.
 * Declaration happens before any translation, which is what lets the reader
 * side go lock-free.
 */
typedef struct DfRegFile {
    const char *base;
    const char *const *names;
    uint32_t off;
    uint32_t stride;
    uint32_t elem;
    uint32_t n;
} DfRegFile;

static DfRegFile df_regfile[INSN_DF_MAX_REGFILES];
static unsigned df_n_regfile;

void insn_dataflow_declare_regfile(const char *base, const char *const *names,
                                   uint32_t off, uint32_t stride,
                                   uint32_t elem, uint32_t n)
{
    if ((base == NULL && names == NULL) || n == 0 || elem == 0) {
        return;
    }
    /*
     * A file of more than one register needs a stride that covers its
     * elements, or two of them share bytes and no offset could tell them
     * apart.  Refusing is the only honest answer to a declaration that
     * cannot be true.
     */
    if (n > 1 && stride < elem) {
        return;
    }
    for (unsigned i = 0; i < df_n_regfile; i++) {
        if (df_regfile[i].off == off && df_regfile[i].n == n) {
            return;             /* the same declaration twice */
        }
    }
    if (df_n_regfile >= INSN_DF_MAX_REGFILES) {
        return;
    }
    df_regfile[df_n_regfile++] = (DfRegFile){
        .base = base, .names = names, .off = off,
        .stride = n > 1 ? stride : elem, .elem = elem, .n = n,
    };
}

/*
 * THE REPRESENTATION SELECTORS.  See insn_dataflow_declare_repr_selector()
 * in the header for what one is and why the target has to say so.
 *
 * Kept as env OFFSETS rather than TCGTemp pointers: the temps belong to a
 * TCGContext and the declaration is made once at target init, while the
 * question is asked per translation from whichever context is current.  The
 * offset is the identity every other declaration in this file uses.
 */
static uint32_t df_selector[INSN_DF_MAX_SELECTORS];
static unsigned df_n_selector;

void insn_dataflow_declare_repr_selector(const void *ts)
{
    const TCGTemp *t = ts;
    uint32_t off;

    if (t == NULL || t->kind != TEMP_GLOBAL) {
        return;
    }
    off = (uint32_t)t->mem_offset;
    for (unsigned i = 0; i < df_n_selector; i++) {
        if (df_selector[i] == off) {
            return;                 /* the same declaration twice */
        }
    }
    if (df_n_selector >= INSN_DF_MAX_SELECTORS) {
        return;
    }
    df_selector[df_n_selector++] = off;
}

bool insn_dataflow_reg_is_repr_selector(unsigned i)
{
    uint32_t off;

    if (df_n_selector == 0 || !insn_dataflow_reg_name(i, &off, NULL)) {
        return false;
    }
    for (unsigned k = 0; k < df_n_selector; k++) {
        if (df_selector[k] == off) {
            return true;
        }
    }
    return false;
}

bool insn_dataflow_field_reg(uint32_t off, uint32_t size,
                             char *buf, size_t buflen)
{
    TCGContext *s = tcg_ctx;

    if (buf == NULL || buflen == 0 || size == 0 ||
        size == DF_FIELD_UNBOUNDED) {
        return false;
    }
    /*
     * A TCG GLOBAL first.  An env range can coincide with one -- a target
     * that reaches its own flags word by ld/st, or a helper row naming the
     * bytes a global also names -- and the global's name is the same answer
     * arrived at by a shorter route.  Asking here means the declarations
     * below only have to cover what the globals do NOT.
     */
    for (unsigned i = 0; i < (unsigned)s->nb_globals; i++) {
        uint32_t goff, gsize;
        const char *nm = insn_dataflow_reg_name(i, &goff, &gsize);

        if (nm && off >= goff && off - goff + size <= gsize) {
            pstrcpy(buf, buflen, nm);
            return true;
        }
    }
    for (unsigned i = 0; i < df_n_regfile; i++) {
        const DfRegFile *r = &df_regfile[i];
        uint32_t d, idx, within;

        if (off < r->off) {
            continue;
        }
        d = off - r->off;
        idx = d / r->stride;
        if (idx >= r->n) {
            continue;
        }
        within = d - idx * r->stride;
        /*
         * REACHING PAST THE REGISTER IS NOT A NAME FROM THIS FILE.  A helper
         * handed the whole vector file starts at the same byte as a store of
         * its first register; calling that one xmm0 would publish a set
         * short by thirty-one registers, which is the one error direction
         * this whole file treats as a defect rather than a loss of accuracy.
         *
         * It moves to the NEXT declaration rather than refusing outright,
         * because one target's registers can nest inside another's: x86's
         * mm<n> is the low half of the physical x87 slot fpregs[n], and the
         * x87 stack is declared as the whole CONTAINER because ST(i) is
         * relative to a run-time top.  A read of eight bytes at fpregs[n] is
         * mm<n>; a read of all 128 is the container.  Both are true and only
         * the width tells them apart, so the narrow file has to be able to
         * decline without taking the wide one down with it.  If no
         * declaration fits, the loop still ends in the same refusal -- this
         * is a no-op for every target whose declared files do not overlap.
         */
        if (within + size > r->elem) {
            continue;
        }
        if (r->names) {
            if (r->names[idx] == NULL) {
                return false;
            }
            pstrcpy(buf, buflen, r->names[idx]);
        } else if (r->n == 1) {
            pstrcpy(buf, buflen, r->base);
        } else {
            snprintf(buf, buflen, "%s%u", r->base, idx);
        }
        return true;
    }
    return false;
}

bool insn_dataflow_prov_field_reg(unsigned bit, char *buf, size_t buflen)
{
    unsigned base = tcg_ctx->nb_globals;

    if (!df || bit < base || bit - base >= df_nslots) {
        return false;
    }
    return insn_dataflow_field_reg(df_slot_off[bit - base],
                                   df_slot_size[bit - base], buf, buflen);
}

unsigned insn_dataflow_nregs(void)
{
    return tcg_ctx->nb_globals;
}

const char *insn_dataflow_reg_name(unsigned i, uint32_t *off, uint32_t *size)
{
    TCGContext *s = tcg_ctx;
    const TCGTemp *ts;

    if (i >= (unsigned)s->nb_globals) {
        return NULL;
    }
    ts = &s->temps[i];
    if (ts->kind != TEMP_GLOBAL || ts->mem_base != tcgv_ptr_temp(tcg_env)) {
        return NULL;
    }
    if (off) {
        *off = (uint32_t)ts->mem_offset;
    }
    if (size) {
        *size = tcg_type_size(ts->base_type);
    }
    return ts->name;
}
