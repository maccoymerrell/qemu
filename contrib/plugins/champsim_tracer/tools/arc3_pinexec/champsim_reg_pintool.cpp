/*
 * ChampSim Tracer — Intel PIN register execution reference (x86_64).
 *
 * Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHAT THIS IS FOR
 *
 * The register arm of the PIN cross-check used to be the widened ChampSim
 * `input_instr` (8 destination / 16 source slots).  Two things were wrong
 * with it as a REFERENCE, and both of them made a green number mean less
 * than it looked:
 *
 *   1. It carried register IDENTIFIERS ONLY.  The value axis — what the
 *      register actually held — had no reference at all on x86_64, so
 *      "register VALUES" read NONE in the facet table while riscv64 read
 *      EXEC against Spike.
 *
 *   2. Its operand list came from `INS_RegR`/`INS_RegW`, which report the
 *      EXPLICIT operands.  An implicit read — the flags `adc` consumes,
 *      the `rsp` `push` decrements, the `rcx` a `rep` prefix counts down —
 *      was simply absent, so the reference's SILENCE proved nothing and
 *      only its positive evidence could be scored.  A one-directional
 *      reference cannot convict a tracer of naming too much or of naming
 *      too little; it can only agree.
 *
 * This tool fixes both.
 *
 * OPERANDS COME FROM XED'S FULL OPERAND LIST, NOT FROM PIN'S ACCESSORS.
 * Every static instruction is re-decoded here with `xed_decode`, and the
 * template operand list (`xed_inst_operand` over `xed_inst_noperands`) is
 * walked in full — EXPLICIT and SUPPRESSED alike, plus the memory
 * addressing registers (BASE0/BASE1/INDEX/SEG0/SEG1) and the RFLAGS
 * read/write sets from `xed_decoded_inst_get_rflags_info`.  That list is
 * the decode tables' own account of what the instruction touches, so its
 * silence IS evidence: a register absent from it is a register the
 * instruction does not name.
 *
 * THE DECODE SETS CET.  PIN's own decode leaves the CET operand unset,
 * which makes `f3 0f 1e fa` decode as `nop edx, edi` — a two-register READ
 * of registers `endbr64` does not touch — and `f3 48 0f 1e c8` (`rdsspq
 * rax`) decode as a register-reading nop.  Those two encodings alone were
 * 249 of the 266 measured TRACER-SUBSET rows in the 2026-08-23 pass, all
 * of them reference defects rather than tracer defects.
 * `xed3_operand_set_cet(&d, 1)` before the decode removes the whole class.
 *
 * VALUES COME FROM THE CONTEXT.  `IARG_CONST_CONTEXT` is taken once per
 * instruction and `PIN_GetContextRegval` reads every named register out of
 * it, at full architectural width (`REG_FullRegName`), which is the same
 * thing the tracer's `regdata` reads back through QEMU's register API.
 *
 * DESTINATION VALUES ARE READ ONE INSTRUCTION LATE, BY CONSTRUCTION, for
 * the same reason the memop tool defers store data: a destination's value
 * only exists after the instruction retires, and IPOINT_AFTER does not
 * exist on control-flow instructions and is defined on a REP-prefixed
 * instruction only after its final iteration.  So the record for
 * instruction N is held in a one-deep buffer and its destinations are read
 * from the CONTEXT of instruction N+1's IPOINT_BEFORE, at which point N has
 * committed and N+1 has not yet run.  Sources are read from the
 * instruction's own IPOINT_BEFORE context, where they are still the
 * pre-execution values.  The final buffered record is flushed from Fini.
 *
 * NOTHING IS INFERRED FROM SILENCE.  Registers that did not fit, values
 * that were truncated, and registers with no readable context slot are all
 * COUNTED and FLAGGED per entry, so a reader can tell "we looked and it
 * agreed" from "we never looked".
 */

#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "pin.H"

extern "C" {
#include "xed-interface.h"
}

/* Per-record capacity.  All three are recorded in the sidecar header so a
 * reader can never assume them. */
#define CST_REG_NSRC   16
#define CST_REG_NDST   12
#define CST_REG_VBYTES 32

/* Per-entry flag bits. */
#define CST_RF_EXPLICIT  0x01  /* named by an EXPLICIT operand */
#define CST_RF_IMPLICIT  0x02  /* named only by a SUPPRESSED operand */
#define CST_RF_MEMADDR   0x04  /* a memory addressing register */
#define CST_RF_RFLAGS    0x08  /* contributed by the RFLAGS read/write set */
#define CST_RF_NOVALUE   0x10  /* no readable context slot: value is absent */
#define CST_RF_TRUNC     0x20  /* register wider than CST_REG_VBYTES */

#pragma pack(push, 1)
struct reg_entry {
  UINT16 pin_reg;   /* PIN REG enum, full-width; 0 when unmapped */
  UINT16 xed_reg;   /* xed_reg_enum_t as decoded (NOT widened) */
  UINT8  width;     /* bytes of the full register, 0 when unknown */
  UINT8  got;       /* value bytes actually placed in `val` */
  UINT8  flags;
  UINT8  pad;
  UINT8  val[CST_REG_VBYTES];
};

struct reg_rec {
  UINT64 ip;
  UINT8  is_branch;
  UINT8  taken;
  UINT8  len;        /* real instruction length, 1..15 */
  UINT8  decode_ok;  /* XED decoded this encoding */
  UINT8  n_src;      /* TRUE count of named source registers */
  UINT8  n_dst;      /* TRUE count of named destination registers */
  UINT8  src_rec;    /* how many this record actually holds */
  UINT8  dst_rec;
  UINT8  bytes[16];  /* raw encoding, zero-padded */
  reg_entry src[CST_REG_NSRC];
  reg_entry dst[CST_REG_NDST];
};
#pragma pack(pop)

static const UINT32 REC_SIZE = sizeof(reg_rec);

/* ================================================================== */

static UINT64 skippedInstrCount = 0;
static UINT64 tracedCumulativeInstructions = 0;
static bool tracingActive = false;
static bool g_write = false;

static UINT64 g_srcOverflow = 0;
static UINT64 g_dstOverflow = 0;
static UINT64 g_novalue = 0;
static UINT64 g_trunc = 0;
static UINT64 g_written = 0;
static UINT64 g_decodeFail = 0;

static std::ofstream outfile;
static std::string g_outpath;

/* Every register enum this run actually emitted, so the reader needs no
 * hard-coded copy of either enum.  A hard-coded table is a second place
 * for the mapping to be wrong in. */
static std::map<UINT16, std::string> g_xedNames;
static std::map<UINT16, std::string> g_pinNames;

static reg_rec cur;
static reg_rec held;
static bool held_valid = false;

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "reg.bin",
                                 "output file for the register reference stream");
KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0",
                                  "instructions to skip before recording");
KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "t", "1000000",
                                   "instructions to record");
static UINT64 g_skip = 0;
static UINT64 g_trace = 0;

INT32 Usage()
{
  std::cerr << "ChampSim Tracer PIN register reference (id + VALUE, explicit + implicit)"
            << std::endl
            << "  -o out  -s skip  -t trace" << std::endl
            << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

/* ---------------------------------------------------------------- gate */
/* Identical in shape to the memop arm's Gate(): a REP-prefixed instruction
 * consumes exactly ONE slot of the skip/trace budget (architectural clock,
 * matching QEMU's icount) while still emitting one record per iteration. */
static VOID PIN_FAST_ANALYSIS_CALL Gate(BOOL hasRealRep, BOOL isFirstRep)
{
  BOOL countsAsOne = !hasRealRep || isFirstRep;
  if (countsAsOne) {
    if (!tracingActive) {
      if (skippedInstrCount > g_skip) {
        tracingActive = true;
      } else {
        ++skippedInstrCount;
        g_write = false;
        return;
      }
    }
    ++tracedCumulativeInstructions;
    if (tracedCumulativeInstructions > g_trace) {
      tracingActive = false;
      g_write = false;
      std::cout << "Reached instruction limit: " << g_trace << ". Stopping trace."
                << std::endl;
      PIN_ExitApplication(0);
      return;
    }
  }
  g_write = tracingActive;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL DoWrite() { return g_write; }

/* -------------------------------------------------- static operand list */

struct StaticSlot {
  REG    pinreg;    /* full-width PIN register, REG_INVALID_ when unmapped */
  UINT16 xedreg;
  UINT8  width;
  UINT8  flags;
};

struct StaticInfo {
  UINT8 length;
  UINT8 decode_ok;
  UINT8 bytes[16];
  UINT8 nsrc, ndst;      /* TRUE counts, uncapped */
  UINT8 nsrc_rec, ndst_rec;
  StaticSlot src[CST_REG_NSRC];
  StaticSlot dst[CST_REG_NDST];
};

/* A register PIN can read out of a CONTEXT.  Anything else is recorded by
 * NAME with CST_RF_NOVALUE set — a gap a reader can see, never a zero that
 * reads as data. */
static bool ContextReadable(REG r)
{
  if (r == REG_INVALID_ || r == REG_NONE)
    return false;
  if (!REG_is_application(r))
    return false;
  if (REG_is_gr(r) || REG_is_seg(r) || REG_is_seg_base(r) || REG_is_mm(r) ||
      REG_is_xmm_ymm_zmm(r) || REG_is_k_mask(r) || REG_is_st(r) ||
      REG_is_flags_any_size_type(r) || r == LEVEL_BASE::REG_RIP || r == LEVEL_BASE::REG_MXCSR)
    return true;
  return false;
}

/* XED register classes this tool will hand to INS_XedExactMapToPinReg.
 * That routine ASSERTS when no exact map exists, so it is only ever called
 * for classes known to have one; everything else is recorded by its XED
 * name with no value. */
static bool MappableClass(xed_reg_enum_t r)
{
  switch (xed_reg_class(r)) {
    case XED_REG_CLASS_GPR:
    case XED_REG_CLASS_GPR8:
    case XED_REG_CLASS_GPR16:
    case XED_REG_CLASS_GPR32:
    case XED_REG_CLASS_GPR64:
    case XED_REG_CLASS_XMM:
    case XED_REG_CLASS_YMM:
    case XED_REG_CLASS_ZMM:
    case XED_REG_CLASS_MASK:
    case XED_REG_CLASS_X87:
    case XED_REG_CLASS_MMX:
    case XED_REG_CLASS_SR:
    case XED_REG_CLASS_FLAGS:
    case XED_REG_CLASS_IP:
      return true;
    default:
      return false;
  }
}

static void AddSlot(StaticInfo* si, bool is_dst, xed_reg_enum_t xr, UINT8 flags)
{
  if (xr == XED_REG_INVALID || xr == XED_REG_ERROR)
    return;

  REG pr = REG_INVALID_;
  if (MappableClass(xr)) {
    pr = INS_XedExactMapToPinReg(xr);
    if (pr != REG_INVALID_ && pr != REG_NONE)
      pr = REG_FullRegName(pr);
  }

  StaticSlot* arr = is_dst ? si->dst : si->src;
  UINT8 cap = is_dst ? CST_REG_NDST : CST_REG_NSRC;
  UINT8* n = is_dst ? &si->ndst : &si->nsrc;
  UINT8* nrec = is_dst ? &si->ndst_rec : &si->nsrc_rec;

  /* A set, keyed on the FULL register: `al` and `rax` are one register.
   * When the same register arrives twice the flags union, so an operand
   * that is both explicit and memory-addressing says so. */
  for (UINT8 i = 0; i < *nrec; i++) {
    bool same = (pr != REG_INVALID_ && arr[i].pinreg == pr) ||
                (pr == REG_INVALID_ && arr[i].pinreg == REG_INVALID_ &&
                 arr[i].xedreg == (UINT16)xr);
    if (same) {
      arr[i].flags |= flags;
      return;
    }
  }

  ++*n;
  if (*nrec >= cap)
    return;

  StaticSlot* s = &arr[*nrec];
  s->pinreg = pr;
  s->xedreg = (UINT16)xr;
  s->flags = flags;
  s->width = 0;
  if (ContextReadable(pr)) {
    UINT32 sz = REG_Size(pr);
    s->width = (UINT8)(sz > 255 ? 255 : sz);
    if (sz > CST_REG_VBYTES)
      s->flags |= CST_RF_TRUNC;
  } else {
    s->flags |= CST_RF_NOVALUE;
  }
  if (pr != REG_INVALID_ && pr != REG_NONE)
    g_pinNames[(UINT16)pr] = REG_StringShort(pr);
  g_xedNames[(UINT16)xr] = xed_reg_enum_t2str(xr);
  ++*nrec;
}

/* Walk XED's FULL template operand list for one static instruction. */
static void BuildOperands(StaticInfo* si)
{
  xed_state_t dstate;
  xed_state_init2(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_decoded_inst_t d;
  xed_decoded_inst_zero_set_mode(&d, &dstate);
  /* The whole point: PIN's own decode leaves this clear, and `endbr64`
   * then decodes as a two-register-reading nop. */
  xed3_operand_set_cet(&d, 1);

  xed_error_enum_t err = xed_decode(&d, si->bytes, si->length);
  if (err != XED_ERROR_NONE) {
    si->decode_ok = 0;
    ++g_decodeFail;
    return;
  }
  si->decode_ok = 1;

  /* REFERENCE CORRECTION, adjudicated, not assumed.
   *
   * XED's template marks `leave`'s rSP read-write.  The SDM defines LEAVE
   * as `rSP <- rBP; POP rBP`: the incoming rSP is DISCARDED, never read,
   * and iced-x86 agrees (`RSP WRITE`, `RBP READ_WRITE`).  Left uncorrected
   * this scores every `leave` as the tracer dropping a source it is right
   * not to name -- 19 rows in the 2026-08-23 pass. */
  const bool leave_form = (xed_decoded_inst_get_iclass(&d) == XED_ICLASS_LEAVE);

  const xed_inst_t* xi = xed_decoded_inst_inst(&d);
  unsigned int n = xed_inst_noperands(xi);
  for (unsigned int i = 0; i < n; i++) {
    const xed_operand_t* op = xed_inst_operand(xi, i);
    xed_operand_enum_t nm = xed_operand_name(op);

    bool is_reg = xed_operand_is_register(nm);
    bool is_mar = xed_operand_is_memory_addressing_register(nm);
    if (!is_reg && !is_mar)
      continue;

    xed_reg_enum_t xr = xed_decoded_inst_get_reg(&d, nm);
    if (xr == XED_REG_INVALID)
      continue;

    UINT8 flags = 0;
    if (is_mar) {
      flags |= CST_RF_MEMADDR;
    }
    flags |= (xed_operand_operand_visibility(op) == XED_OPVIS_EXPLICIT)
                 ? CST_RF_EXPLICIT
                 : CST_RF_IMPLICIT;

    /* XED does not name the stack pointer as a written register on
     * `push`/`pop`/`call`/`ret`/`leave`.  It expresses the update through
     * the XED_REG_STACKPUSH / XED_REG_STACKPOP pseudo-registers, whose
     * whole meaning is "rSP is stepped".  As a TEMPLATE operand that is a
     * WRITE and nothing else: `leave` steps rSP without reading it (it
     * loads rSP from rBP first), and a reference that scored a read there
     * would convict the tracer of dropping a source it is right not to
     * name.  The READ, where there is one, comes from the memory operand
     * below, whose base register IS the stack pointer on push/pop. */
    if (xr == XED_REG_STACKPUSH || xr == XED_REG_STACKPOP) {
      AddSlot(si, true, XED_REG_RSP, (UINT8)(flags | CST_RF_IMPLICIT));
      continue;
    }

    /* A memory addressing register is READ by the address computation
     * whatever the operand template's own action says. */
    bool suppress_read = leave_form && !is_mar &&
                         (xr == XED_REG_RSP || xr == XED_REG_ESP ||
                          xr == XED_REG_SP);

    /* The DECODED action, not the raw template action.  A CONDITIONALLY
     * WRITTEN operand is also a SOURCE: when the condition fails the
     * register keeps the value it already held, so the old value flows to
     * the result.  That is what `cmov` does, what iced-x86 encodes as
     * COND_WRITE, and what the tracer records -- 2,094 rows in the
     * 2026-08-23 pass were the reference disagreeing with itself about
     * this one fact. */
    xed_operand_action_enum_t act = xed_decoded_inst_operand_action(&d, i);
    bool acts_read = (act == XED_OPERAND_ACTION_R ||
                      act == XED_OPERAND_ACTION_RW ||
                      act == XED_OPERAND_ACTION_RCW ||
                      act == XED_OPERAND_ACTION_CR ||
                      act == XED_OPERAND_ACTION_CRW ||
                      act == XED_OPERAND_ACTION_CW);
    bool acts_written = (act == XED_OPERAND_ACTION_W ||
                         act == XED_OPERAND_ACTION_RW ||
                         act == XED_OPERAND_ACTION_RCW ||
                         act == XED_OPERAND_ACTION_CW ||
                         act == XED_OPERAND_ACTION_CRW);

    if ((is_mar || acts_read) && !suppress_read)
      AddSlot(si, false, xr, flags);
    if (!is_mar && acts_written)
      AddSlot(si, true, xr, flags);
  }

  /* MEMORY ADDRESSING REGISTERS.  XED carries BASE0/INDEX/SEG0 in the
   * TEMPLATE operand list only where the memory operand is SUPPRESSED
   * (`push`, `pop`, `call`, `ret`, `leave`, the string ops).  For an
   * EXPLICIT memory operand they live in the decoded instruction's
   * operand storage instead, and a walk of the template list alone misses
   * every base and index register of every ordinary `mov (%rbx), %rax`.
   * Enumerate the memory operands directly.
   *
   * Segment registers: in 64-bit mode the CS/DS/ES/SS bases are
   * architecturally zero and no address computation reads them, so only
   * FS and GS -- the two that carry a base -- are scored.  A reference
   * that named DS on every memory access would convict the tracer of a
   * subset on every memory access. */
  /* A string operation steps its pointer register by the direction flag on
   * every iteration.  XED's operand template names rDI/rSI only as the
   * memory base, never as a written register, so the reference has to
   * supply the update the ISA guarantees. */
  bool stringop = (xed_decoded_inst_get_category(&d) == XED_CATEGORY_STRINGOP);

  unsigned int nmem = xed_decoded_inst_number_of_memory_operands(&d);
  for (unsigned int m = 0; m < nmem; m++) {
    xed_reg_enum_t regs[3];
    regs[0] = xed_decoded_inst_get_base_reg(&d, m);
    regs[1] = xed_decoded_inst_get_index_reg(&d, m);
    regs[2] = xed_decoded_inst_get_seg_reg(&d, m);
    for (int t = 0; t < 3; t++) {
      xed_reg_enum_t xr = regs[t];
      if (xr == XED_REG_INVALID)
        continue;
      if (xr == XED_REG_STACKPUSH || xr == XED_REG_STACKPOP) {
        AddSlot(si, false, XED_REG_RSP, CST_RF_IMPLICIT | CST_RF_MEMADDR);
        AddSlot(si, true, XED_REG_RSP, CST_RF_IMPLICIT | CST_RF_MEMADDR);
        continue;
      }
      if (t == 2 && xr != XED_REG_FS && xr != XED_REG_GS)
        continue;
      AddSlot(si, false, xr, CST_RF_IMPLICIT | CST_RF_MEMADDR);
      if (stringop && t == 0 &&
          (xr == XED_REG_RDI || xr == XED_REG_RSI ||
           xr == XED_REG_EDI || xr == XED_REG_ESI))
        AddSlot(si, true, xr, CST_RF_IMPLICIT | CST_RF_MEMADDR);
    }
  }

  /* RFLAGS: XED keeps the flag read/write sets outside the operand list
   * for some forms, so take them from the simple-flag record too.  The
   * slot list is a set, so a doubly-named RFLAGS costs nothing. */
  if (xed_decoded_inst_uses_rflags(&d)) {
    const xed_simple_flag_t* f = xed_decoded_inst_get_rflags_info(&d);
    if (f) {
      if (xed_simple_flag_reads_flags(f))
        AddSlot(si, false, XED_REG_RFLAGS, CST_RF_IMPLICIT | CST_RF_RFLAGS);
      if (xed_simple_flag_writes_flags(f))
        AddSlot(si, true, XED_REG_RFLAGS, CST_RF_IMPLICIT | CST_RF_RFLAGS);
    }
  }
}

/* ------------------------------------------------------- flush / build */

static VOID ReadInto(const CONTEXT* ctxt, reg_entry* e)
{
  if (e->flags & CST_RF_NOVALUE) {
    ++g_novalue;
    return;
  }
  UINT8 buf[128];
  std::memset(buf, 0, sizeof(buf));
  PIN_GetContextRegval(ctxt, (REG)e->pin_reg, buf);
  UINT32 want = e->width;
  if (want > CST_REG_VBYTES) {
    want = CST_REG_VBYTES;
    ++g_trunc;
  }
  std::memcpy(e->val, buf, want);
  e->got = (UINT8)want;
}

/* Destinations of the HELD record are read from the context of the NEXT
 * instruction's IPOINT_BEFORE: N has retired, N+1 has not begun. */
static VOID FlushHeld(const CONTEXT* ctxt)
{
  if (!held_valid)
    return;
  if (ctxt) {
    for (UINT32 k = 0; k < held.dst_rec; k++)
      ReadInto(ctxt, &held.dst[k]);
  }
  outfile.write(reinterpret_cast<const char*>(&held), REC_SIZE);
  ++g_written;
  held_valid = false;
}

/* Unconditional, never predicated on the tracing gate: a record dropped
 * because a window closed reads as agreement. */
static VOID Flush(const CONTEXT* ctxt) { FlushHeld(ctxt); }

static VOID Reset(VOID* ip, StaticInfo* si, const CONTEXT* ctxt)
{
  std::memset(&cur, 0, sizeof(cur));
  cur.ip = (UINT64)(ADDRINT)ip;
  cur.len = si->length;
  cur.decode_ok = si->decode_ok;
  std::memcpy(cur.bytes, si->bytes, sizeof(cur.bytes));
  cur.n_src = si->nsrc;
  cur.n_dst = si->ndst;
  cur.src_rec = si->nsrc_rec;
  cur.dst_rec = si->ndst_rec;
  if (si->nsrc > si->nsrc_rec)
    g_srcOverflow += si->nsrc - si->nsrc_rec;
  if (si->ndst > si->ndst_rec)
    g_dstOverflow += si->ndst - si->ndst_rec;

  for (UINT8 k = 0; k < si->nsrc_rec; k++) {
    cur.src[k].pin_reg = (UINT16)si->src[k].pinreg;
    cur.src[k].xed_reg = si->src[k].xedreg;
    cur.src[k].width = si->src[k].width;
    cur.src[k].flags = si->src[k].flags;
    /* Sources are pre-execution values: this instruction's own context. */
    ReadInto(ctxt, &cur.src[k]);
  }
  for (UINT8 k = 0; k < si->ndst_rec; k++) {
    cur.dst[k].pin_reg = (UINT16)si->dst[k].pinreg;
    cur.dst[k].xed_reg = si->dst[k].xedreg;
    cur.dst[k].width = si->dst[k].width;
    cur.dst[k].flags = si->dst[k].flags;
    /* value filled at the next instruction's Flush() */
  }
}

static VOID BranchOrNot(UINT32 taken)
{
  cur.is_branch = 1;
  cur.taken = (UINT8)taken;
}

static VOID Commit()
{
  std::memcpy(&held, &cur, sizeof(held));
  held_valid = true;
}

/* ---------------------------------------------------- instrumentation */

VOID Instruction(INS ins, VOID* v)
{
  StaticInfo* si = new StaticInfo();
  std::memset(si, 0, sizeof(*si));
  USIZE sz = INS_Size(ins);
  si->length = (unsigned char)sz;
  if (sz > sizeof(si->bytes))
    sz = sizeof(si->bytes);
  PIN_SafeCopy(si->bytes, (VOID*)INS_Address(ins), sz);
  BuildOperands(si);

  BOOL hasRealRep = INS_HasRealRep(ins);

  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Gate, IARG_FAST_ANALYSIS_CALL,
                 IARG_BOOL, hasRealRep, IARG_FIRST_REP_ITERATION, IARG_END);

  /* Ungated: the previous record's destinations settle here. */
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Flush, IARG_CONST_CONTEXT, IARG_END);

  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Reset, IARG_INST_PTR, IARG_PTR, si,
                     IARG_CONST_CONTEXT, IARG_END);

  if (INS_IsBranch(ins)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);
  }

  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Commit, IARG_END);
}

VOID Fini(INT32 code, VOID* v)
{
  /* The last record has no successor instruction, so its destinations were
   * never read.  Write it with them ABSENT rather than with stale zeros. */
  if (held_valid) {
    for (UINT32 k = 0; k < held.dst_rec; k++) {
      held.dst[k].got = 0;
      held.dst[k].flags |= CST_RF_NOVALUE;
    }
  }
  FlushHeld(NULL);
  outfile.flush();
  outfile.close();

  std::ofstream side((g_outpath + ".regnames").c_str(), std::ios_base::trunc);
  side << "# recsize " << REC_SIZE << "\n";
  side << "# nsrc " << CST_REG_NSRC << " ndst " << CST_REG_NDST
       << " vbytes " << CST_REG_VBYTES << "\n";
  for (std::map<UINT16, std::string>::const_iterator it = g_xedNames.begin();
       it != g_xedNames.end(); ++it)
    side << "xed " << it->first << " " << it->second << "\n";
  for (std::map<UINT16, std::string>::const_iterator it = g_pinNames.begin();
       it != g_pinNames.end(); ++it)
    side << "pin " << it->first << " " << it->second << "\n";
  side.close();

  std::cerr << "[reg-ref] recsize=" << REC_SIZE
            << " nsrc=" << CST_REG_NSRC
            << " ndst=" << CST_REG_NDST
            << " vbytes=" << CST_REG_VBYTES
            << " skipped=" << skippedInstrCount
            << " traced=" << tracedCumulativeInstructions
            << " written=" << g_written
            << " src_overflow=" << g_srcOverflow
            << " dst_overflow=" << g_dstOverflow
            << " novalue=" << g_novalue
            << " truncated=" << g_trunc
            << " decode_fail=" << g_decodeFail
            << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  xed_tables_init();

  g_skip = KnobSkipInstructions.Value();
  g_trace = KnobTraceInstructions.Value();
  g_outpath = KnobOutputFile.Value();

  outfile.open(g_outpath.c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!outfile) {
    std::cerr << "cannot open output file" << std::endl;
    exit(1);
  }

  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
