/*
 * ChampSim Tracer — Intel PIN memop execution reference (x86_64).
 *
 * Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHAT THIS IS FOR
 *
 * The register arm of the PIN cross-check (tool_wide, the widened
 * ChampSim `input_instr`) carries memory operands only as an EFFECTIVE
 * ADDRESS, de-duplicated into two destination and four source slots, with
 * no access width and no value.  Memop COUNT could therefore be scored,
 * ADDRESS could be scored as a per-region constant delta, and DATA — the
 * value actually read or written — could not be scored at all.
 *
 * This tool records, per dynamic instruction and per memory operand:
 *
 *   COUNT    the true number of load and store memops, uncapped, kept
 *            separately from the number of them the record had room for,
 *            so an over-capacity instruction is VISIBLE rather than being
 *            silently scored as agreement;
 *   ADDRESS  the effective address of each access, in operand order (not
 *            de-duplicated: two accesses to the same address are two
 *            accesses);
 *   WIDTH    the access size in bytes;
 *   DATA     the bytes read or written, up to CST_PIN_DBYTES, together
 *            with how many bytes PIN_SafeCopy actually delivered.
 *
 * STORE VALUES ARE READ ONE INSTRUCTION LATE, BY CONSTRUCTION.  A store's
 * value only exists after the instruction retires, and IPOINT_AFTER is not
 * available on control-flow instructions (call, ret, jmp) and is defined
 * on a REP-prefixed instruction only after the final iteration — precisely
 * the two shapes whose store data matters most (`call` pushes the return
 * address; `rep movsq` stores once per iteration).  So the record for
 * instruction N is held in a one-deep buffer and written out at the
 * IPOINT_BEFORE of instruction N+1, at which point N's stores have
 * committed and PIN_SafeCopy reads the settled bytes.  The final buffered
 * record is flushed from Fini.
 *
 * The flush hook is deliberately UNCONDITIONAL — not predicated on the
 * tracing gate — so that the last record of a tracing window is never lost
 * to the window closing.  A dropped record reads as agreement.
 */

#include <cstring>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "pin.H"

/* Per-record capacity.  Both are recorded in the file header so a reader
 * can never assume them. */
#define CST_PIN_NMEM   4    /* memops of each direction kept per record */
#define CST_PIN_DBYTES 32   /* value bytes kept per memop */

#pragma pack(push, 1)
struct memop_rec {
  UINT64 ip;
  UINT8  is_branch;
  UINT8  taken;
  UINT8  n_ld;       /* TRUE load count for this dynamic instruction */
  UINT8  n_st;       /* TRUE store count */
  UINT8  ld_rec;     /* how many loads this record actually holds */
  UINT8  st_rec;
  UINT8  len;        /* real instruction length, 1..15 */
  UINT8  pad;
  UINT8  bytes[16];  /* raw encoding, zero-padded */
  UINT64 ld_ea[CST_PIN_NMEM];
  UINT64 st_ea[CST_PIN_NMEM];
  UINT32 ld_sz[CST_PIN_NMEM];
  UINT32 st_sz[CST_PIN_NMEM];
  UINT8  ld_got[CST_PIN_NMEM];   /* bytes PIN_SafeCopy delivered */
  UINT8  st_got[CST_PIN_NMEM];
  UINT8  ld_data[CST_PIN_NMEM][CST_PIN_DBYTES];
  UINT8  st_data[CST_PIN_NMEM][CST_PIN_DBYTES];
};
#pragma pack(pop)

static const UINT32 REC_SIZE = sizeof(memop_rec);

struct StaticBytes {
  unsigned char length;
  unsigned char bytes[16];
};

/* ================================================================== */

static UINT64 skippedInstrCount = 0;
static UINT64 tracedCumulativeInstructions = 0;
static bool tracingActive = false;
static bool g_write = false;

/* Over-capacity accounting: an instruction whose memops did not fit is a
 * measurement we did not take, and it is counted, never inferred from
 * silence. */
static UINT64 g_ldOverflow = 0;
static UINT64 g_stOverflow = 0;
static UINT64 g_dataTruncated = 0;   /* memops wider than CST_PIN_DBYTES */
static UINT64 g_shortCopy = 0;       /* PIN_SafeCopy delivered fewer bytes */
static UINT64 g_written = 0;

static std::ofstream outfile;

/* One-deep record buffer: `cur` is the instruction being built, `held` is
 * the previous instruction, waiting for its store values. */
static memop_rec cur;
static memop_rec held;
static bool held_valid = false;

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "memop.bin",
                                 "output file for the memop reference stream");
KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0",
                                  "instructions to skip before recording");
KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "t", "1000000",
                                   "instructions to record");
static UINT64 g_skip = 0;
static UINT64 g_trace = 0;

INT32 Usage()
{
  std::cerr << "ChampSim Tracer PIN memop reference (count / address / width / data)"
            << std::endl
            << "  -o out  -s skip  -t trace" << std::endl
            << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

/* ---------------------------------------------------------------- gate */
/* Identical in shape to the register arm's Gate(): a REP-prefixed
 * instruction consumes exactly ONE slot of the skip/trace budget
 * (architectural clock, matching QEMU's icount) while still emitting one
 * record per iteration. */
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

/* ------------------------------------------------------- flush / build */

static VOID FlushHeld()
{
  if (!held_valid)
    return;
  for (UINT32 k = 0; k < held.st_rec; k++) {
    UINT32 want = held.st_sz[k];
    if (want > CST_PIN_DBYTES) {
      want = CST_PIN_DBYTES;
      ++g_dataTruncated;
    }
    size_t got = PIN_SafeCopy(held.st_data[k], (VOID*)(ADDRINT)held.st_ea[k], want);
    held.st_got[k] = (UINT8)got;
    if (got != want)
      ++g_shortCopy;
  }
  outfile.write(reinterpret_cast<const char*>(&held), REC_SIZE);
  ++g_written;
  held_valid = false;
}

/* Unconditional: see the header comment.  The previous record's stores
 * have committed by the time any later instruction begins. */
static VOID Flush() { FlushHeld(); }

static VOID Reset(VOID* ip, StaticBytes* sb)
{
  std::memset(&cur, 0, sizeof(cur));
  cur.ip = (UINT64)(ADDRINT)ip;
  cur.len = sb->length;
  std::memcpy(cur.bytes, sb->bytes, sizeof(cur.bytes));
}

static VOID BranchOrNot(UINT32 taken)
{
  cur.is_branch = 1;
  cur.taken = (UINT8)taken;
}

static VOID RecLoad(ADDRINT ea, UINT32 size)
{
  UINT32 k = cur.n_ld;
  ++cur.n_ld;
  if (k >= CST_PIN_NMEM) {
    ++g_ldOverflow;
    return;
  }
  cur.ld_ea[k] = (UINT64)ea;
  cur.ld_sz[k] = size;
  UINT32 want = size;
  if (want > CST_PIN_DBYTES) {
    want = CST_PIN_DBYTES;
    ++g_dataTruncated;
  }
  /* A load's value is settled BEFORE the instruction runs — this is the
   * one direction that needs no deferral. */
  size_t got = PIN_SafeCopy(cur.ld_data[k], (VOID*)ea, want);
  cur.ld_got[k] = (UINT8)got;
  if (got != want)
    ++g_shortCopy;
  cur.ld_rec = (UINT8)(k + 1);
}

static VOID RecStore(ADDRINT ea, UINT32 size)
{
  UINT32 k = cur.n_st;
  ++cur.n_st;
  if (k >= CST_PIN_NMEM) {
    ++g_stOverflow;
    return;
  }
  cur.st_ea[k] = (UINT64)ea;
  cur.st_sz[k] = size;
  cur.st_rec = (UINT8)(k + 1);
}

/* Move the finished record into the one-deep buffer.  It is written out at
 * the next Flush(), once its stores have committed. */
static VOID Commit()
{
  FlushHeld();          /* defensive: Flush() ran first, this is a no-op */
  std::memcpy(&held, &cur, sizeof(held));
  held_valid = true;
}

/* ---------------------------------------------------- instrumentation */

VOID Instruction(INS ins, VOID* v)
{
  StaticBytes* sb = new StaticBytes();
  USIZE sz = INS_Size(ins);
  sb->length = (unsigned char)sz;
  std::memset(sb->bytes, 0, sizeof(sb->bytes));
  if (sz > sizeof(sb->bytes))
    sz = sizeof(sb->bytes);
  PIN_SafeCopy(sb->bytes, (VOID*)INS_Address(ins), sz);

  BOOL hasRealRep = INS_HasRealRep(ins);

  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Gate, IARG_FAST_ANALYSIS_CALL,
                 IARG_BOOL, hasRealRep, IARG_FIRST_REP_ITERATION, IARG_END);

  /* Unconditional flush of the previous record — never gated. */
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Flush, IARG_END);

  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Reset, IARG_INST_PTR, IARG_PTR, sb, IARG_END);

  if (INS_IsBranch(ins)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);
  }

  UINT32 memOperands = INS_MemoryOperandCount(ins);
  for (UINT32 op = 0; op < memOperands; op++) {
    UINT32 opsz = (UINT32)INS_MemoryOperandSize(ins, op);
    /* A read-modify-write operand is ONE operand and TWO memops; it is
     * recorded as both, in the order the hardware performs them. */
    if (INS_MemoryOperandIsRead(ins, op)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)RecLoad,
                         IARG_MEMORYOP_EA, op, IARG_UINT32, opsz, IARG_END);
    }
    if (INS_MemoryOperandIsWritten(ins, op)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)RecStore,
                         IARG_MEMORYOP_EA, op, IARG_UINT32, opsz, IARG_END);
    }
  }

  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)DoWrite, IARG_FAST_ANALYSIS_CALL, IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Commit, IARG_END);
}

VOID Fini(INT32 code, VOID* v)
{
  FlushHeld();
  outfile.flush();
  outfile.close();
  std::cerr << "[memop-ref] recsize=" << REC_SIZE
            << " nmem=" << CST_PIN_NMEM
            << " dbytes=" << CST_PIN_DBYTES
            << " skipped=" << skippedInstrCount
            << " traced=" << tracedCumulativeInstructions
            << " written=" << g_written
            << " ld_overflow=" << g_ldOverflow
            << " st_overflow=" << g_stOverflow
            << " data_truncated=" << g_dataTruncated
            << " short_copy=" << g_shortCopy
            << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  g_skip = KnobSkipInstructions.Value();
  g_trace = KnobTraceInstructions.Value();

  outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!outfile) {
    std::cerr << "cannot open output file" << std::endl;
    exit(1);
  }

  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
