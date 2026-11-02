# ChampSim Tracer — Layer 2: the SHAPE

*The shape is derived from what a real machine does (REALITY) and what the
tracer must record about it (INTENT, Layer 1). It is **not** a description of the
golden plugin's modules. Every mechanism below exists because reality and intent
require it; the golden tracer is consulted only to verify such a mechanism is
achievable and to judge — by one test, **does it record what actually happened,
correctly** — whether the golden's way is kept or changed. Each claim carries its
receipt: `[§n]` = Layer 1 INTENT section; `[fmt]`/`[arch]`/`[qm]` = the
authoritative docs; `[git:sha]` = a golden commit; `[real]` = a fact about the
hardware being modelled.*

By the end, every mechanism and data structure the tracer needs is introduced and
judged, ready for Layer 3 to specify the functions inside each block.

---

## 0. What is being modelled, and what must be produced

**REALITY.** A real core fetches an instruction, decodes it, executes it —
reading and writing registers and memory at computed addresses, with per-lane
structure for vector operations — and at a branch resolves a direction and a
target. A real out-of-order frontend also fetches *speculatively* down the path a
misprediction would take, bounded, and squashes it at retire with no
architectural effect. All of this happens as software threads inside address
spaces at privilege levels, taking synchronous faults and asynchronous
interrupts. `[real][§1]`

**INTENT.** Record, per executed instruction, exactly the facts a
microarchitectural simulator needs to model that core: opcode, registers,
memops, register data, memory data, memory addresses, intra-instruction
dependencies, vector lanes, memop→lane maps — in commit order, on the correct
path **and** the wrong-path shadow, across the four ISAs, every reachable
instruction classified, scoped in system mode by `(thread, asid, privilege)`.
`[§0]`

The tracer is therefore **a faithful recorder of that processing**, and its shape
is the shape of the processing, not of the emulator that hosts it. QEMU is the
instrument the recorder reads through (§H); it is never the backbone.

```
   A. SELECT       which execution to record                     (window/segment/marker)
         |
   B. OBSERVE      one instruction's reality, AT the instruction:
         |            classify it (from QEMU's own decode) and capture its dynamic
         |            facts — memops (addr/size/data), lanes, destination values,
         |            resolved branch edge — in commit order, with no deferral
         v
   C. ASSEMBLE     the per-instruction stream into TRUE basic blocks
         v
   D. REMEMBER     a deduplicated dictionary of true BBs (+ SMC revision identity,
         |            + honest cut-short extent) and one record per dynamic invocation
         v
   E. CONTROL FLOW the resolved branch edge, and the bounded, time-transparent
         |            wrong-path shadow; bulk/iterating ops recorded per access
         v
   F. SCOPE        tag every record (thread, asid, privilege); keep the workload's
         |            synchronous kernel work in program order; exclude async noise  (system mode)
         v
   G. RECORD+WRITE a typed record model  ->  a pluggable serialization backend
         v
            consumed by the microarchitectural simulator

   H. THE INSTRUMENT (QEMU): every arrow above is a fact the recorder needs from
      QEMU, at a stated moment. §H derives those needs and what the base must
      expose to meet them; the golden's base modifications are the evidence it is
      achievable, and the anti-drop ledger, mapped under each need.
```

Everything that follows derives each stage from REALITY + INTENT, states the
mechanism the tracer must have, then judges the golden's current approach.

---

## A. SELECT — which execution is recorded

**REALITY/INTENT `[§3.7]`.** A researcher records a bounded region of a program,
or a chosen process inside a whole system. In user mode the region is named by a
clock position (simpoint — the defining case: N regions, each a **stand-alone**
trace, in one pass — or icount or symbol). In system mode a clock cannot say
*whose* instructions it counts, so the region is named by a **marker** the traced
process runs, and a simpoint schedule is composed onto that marker.

**Mechanism the tracer must have.** A selector that turns capture on over exactly
the chosen span and off outside it; in system mode, a **content-at-vaddr gate**
that admits precisely the contexts mapping the marker bytes — and *only* that, no
root/asid/pid stored or compared as identity `[§3.6]`. Each simpoint region opens
fresh and carries nothing from a prior region (byte-identical whether traced alone
or as one of N). A system run must have a terminator (END marker, shutdown,
dead-latch, stall ceiling) or be refused.

**Judgment.** KEEP — the content-gate and marker windows are reality-forced
(`[§3.6]`: root/ASID identity was tried and failed). The golden's
segment/simpoint managers are an acceptable implementation of "a selector that
yields the chosen execution, each region stand-alone"; Layer 3 judges their
internals by that requirement, not by their current structure.

---

## B. OBSERVE one instruction — the core of the shape

**REALITY.** When an instruction executes, everything about it is knowable *at
that instruction*: its identity, which registers it read and wrote and the values
written, which memory it touched, at what addresses, with what data, feeding which
vector lanes. A real machine does not need the *next* instruction to know what
this one did. `[real]`

**INTENT `[§0, §3.1, §3.3, §3.4]`.** Record that fact set, per instruction, in
commit order.

**Mechanisms the tracer must have:**

1. **Classify from QEMU's behaviour, never a second decoder.** The generic
   opcode, branch type, register in/out sets, intra-instruction dependency
   structure, and lane structure are read from the target's own decode through
   the dataflow ABI and joined against one small vocabulary table. What the
   emulator refuses to execute is what the tracer refuses to record.
   **KEEP** — this is the zero-Capstone spine and the single biggest correctness
   property of the current tree `[§3.1][qm]`. (Capstone is the *offline referee's*
   alone.)

2. **The lane-mask model.** Four dynamic per-slot masks (src / dst / load / store);
   the opcode kind only says *where to read*; the actual mask is computed from the
   operand/memop layout at execution. **KEEP** — required `[§3.4]`; a false lane
   edge costs a consumer as much as a missing one.

3. **Capture the dynamic facts AT the instruction, in commit order** — the memop
   addresses/sizes/data, the per-lane masks and memop→lane map, and the
   destination-register values this instruction wrote. This is the load-bearing
   reality point of the whole layer.

   **CHANGE — this is where the golden is wrong, and it is the example the
   mandate named.** The golden cannot see a block's tail-instruction destination
   values or its branch resolution until QEMU dispatches the *next* translation
   block, so it carries a **deferred (pending-seal) structure**: it holds the
   finished block for a dispatch, stamps a context label at promote, and emits
   late. Judged against ACCURACY, that defer is a defect, not a design: at a
   close the held block publishes a register value from the wrong moment
   (`#79`) and a branch outcome that was never observed (`#81`), and it forces a
   whole apparatus of transfer registers and label-stamping to paper over the
   lateness `[arch][git:6494135e39]`. A real machine commits the instruction's
   results at the instruction; the tracer must capture them there. So the shape
   is **in-instruction capture with no pending-seal slot**, and the instrument is
   made to deliver what that needs (§H.2: a QEMU post-retirement per-instruction
   delivery of committed destination values + resolved edge). The branch *target*
   (direct) and *resolved direction* already arrive in-instruction via existing
   hooks `[git:59f8101261]`, so only the destination-value and
   executed-fragment facts drive this change. Removing the defer dissolves the
   label-stamping/ fault-depth-transfer machinery as a side effect — complexity
   that existed only to serve the lateness.

4. **Synthetic effective address for memory ops QEMU lowers to no memop** —
   software prefetch, cache-line ops, TLB shootdowns, `DC ZVA`, `CBO.ZERO`.
   REALITY: these address memory and a cache/prefetcher model must see the line;
   INTENT: surface the address `[§3.3]`. Mechanism: state the EA at the decode
   site, compute `base + index·scale + disp` at execution. **KEEP** `[qm]`.

---

## C. ASSEMBLE into true basic blocks

**REALITY/consumer `[§3.2]`.** Fetch and the dictionary work at basic-block
granularity: the run of instructions from a branch target up to and including the
next branch. That is the unit a simulator replays and the unit the dictionary
dedups.

**Mechanism the tracer must have.** Fold the per-instruction stream into **true
basic blocks**. This is a genuine obligation, not a golden artifact, because the
instrument does not hand them over ready-made: QEMU's translation block is not a
basic block — it can split one BB across a page boundary and can hold several BBs
when it keeps translating past a mid-block branch (e.g. a MIPS conditional trap).
So the recorder must reconcile the instrument's TB stream to true BBs, sealing a
block at its real terminator wherever the TB boundaries fall. **KEEP the
requirement** `[arch]`; the golden's fragment-splitter + chain-assembler are one
implementation of it, kept only insofar as they produce exactly the true BBs
reality has — Layer 3 specifies them against that test.

---

## D. REMEMBER — the dictionary and the per-invocation record

**REALITY/INTENT `[§3.2]`.** A static block runs many times; its static shape is
fixed, its dynamic facts vary per run; self-modifying code genuinely replaces a
block's instructions. A microarchitecture needs the static shape once and the
dynamic facts every time.

**Mechanisms the tracer must have — stated as requirements:**

- **A deduplicated true-BB dictionary.** One static entry per distinct block
  (PC sequence, generic opcode, branch type, src/dst register IDs, immediate, raw
  bytes, dependency block, lane masks, and a pure-annotation profile a consumer
  may discard). A block's identity is its **template id, not its address**,
  because one address can be several blocks (SMC; and, in system mode, the same VA
  in different address spaces is different code). **KEEP** — reality-forced `[fmt]`.
- **SMC revision identity.** When the correct path re-executes a block whose bytes
  changed, that is a *new block* — a fresh template, the old one retained for the
  records that named it, and a returning prior state reused by content signature
  so A/B/A patching is two blocks, not an unbounded chain. **KEEP the contract**
  (`[§3.2][fmt]`) — reality: code mutates, and each executed state must be recorded
  as what it was.
- **Honest cut-short extent.** A block entered but not finished (a close, a
  control-flow discontinuity) is recorded at the extent that **ran** — never
  claimed whole, never discarded. **KEEP** — ACCURACY: the trace states what
  executed and no more.
- **Tester (b): the dictionary entry declares the field slots it will populate and
  their initial values**, so a consumer pre-allocates per-block storage and a
  wrong-path entry that never had a correct-path visit bases its deltas off those
  initial values cheaply. **CHANGE/ADD** — a record-model addition `[§3.2]`.
- **Optional never-executed coverage** (`static_templates`): a dictionary-only
  entry for the untaken side of a branch, for a consumer reconstructing fetch
  from the binary. **KEEP as optional**, body-byte-identical when off.

**Judgment on complexity.** The golden implements these four requirements with
seven maps plus two `commit` variants and generation-stamped cross-references
`[arch]`. That is the implementation, not the shape. The requirements above are
what reality demands; the map count is a Layer-3 simplicity question — **change
candidate**: collapse whatever the record model and the serialization backend
(§G) subsume (e.g. the backend can own dedup/columnarisation the maps hand-roll),
keeping only the identity/SMC/cut-short semantics reality forces.

---

## E. CONTROL FLOW — the branch edge and the wrong-path shadow

**REALITY `[real][§3.5]`.** A branch resolves a direction and a target; that is a
fetch fact of the instruction itself, not an inference from what runs next (and
for a coincident-edge branch — taken target equals fall-through — only the
resolved direction distinguishes the two). A real OoO frontend fetches down the
mispredicted direction, bounded, through syscalls/traps (it fetches around one and
squashes it), and the excursion has **zero architectural effect** — no guest time,
no memory, no device state.

**Mechanisms the tracer must have:**

- **Record the resolved edge at the branch** — direction and target as the
  instruction's own fact. **KEEP** (the golden landed this as a correctness fix
  `[git:59f8101261,572102ab1b]`; coincident-edge and MIPS BLEZ/BGTZ `[git:adc7e2537a]`
  are stated correctly). Never publish an edge that was not observed — an
  unresolved terminator is declared unresolved, never guessed `[§4.7][fmt]`.
- **Tester (a): the branch direction/target are emitted on nearly every block, so
  they must be the cheapest fields** (low field-IDs under the custom encoding;
  dedicated columns under a database backend — §G makes this free). **CHANGE**
  (hot-field placement) `[§3.5]`.
- **The wrong-path shadow** — a single execution-resolved mispredicted direction,
  bounded by `wpdepth`, walking through a speculatively-fetched syscall/trap at its
  fall-through, stopping only for a real fetch reason (budget exhausted, or an
  instruction fetch the guest MMU cannot translate), never a host-instrument
  limit, and consuming **zero guest time**. **KEEP** — reality-forced `[§3.5,§3.8]`;
  needs a contained speculative mode + time-freeze from the instrument (§H.4).
- **Bulk / iterating memory ops recorded per access (tester d).** REALITY: an x86
  `REP` and an AArch64 FEAT_MOPS copy/set move memory iteration-by-iteration /
  access-by-access; a real machine issues each access. So the recorder **unrolls**
  each iteration (REP) / access (MOPS) as its own one-instruction self-loop
  record, with per-iteration register writes. **KEEP the behaviour** (the
  mechanism exists and its golden defects were fixed:
  `[git:30e2246c0e,e1c3e4a238,6217ac7b98,5a6cb09d0a]`). **Clarified here for
  validation:** the correct behaviour is one record per iteration/access with
  per-iteration register writes and one access per MOPS record; the golden's
  earlier failures to unroll these properly are *bugs fixed in golden*, and
  validation must expect the correct, unrolled behaviour — not the old shape.

---

## F. SCOPE — identity in system mode

**REALITY `[§3.6]`.** The machine runs many threads in many address spaces at
different privileges. The traced process's syscalls and fault handlers are real,
workload-induced execution; asynchronous interrupts (timers, device IRQs) are
unrelated OS noise.

**Mechanisms the tracer must have:**

- **Every record tagged `(thread_id, asid, privilege)`**, where `thread_id` is a
  guest-thread identity (never a vCPU index), `asid` is an address-space *label*
  (never an identity to match across time), and a per-insn `SYSTEM` bit marks
  kernel execution. **KEEP** — reality-forced `[§3.6][arch]`.
- **Content-at-vaddr identity only** (Stage A's gate) — no page-table root/ASID/pid
  as identity. **KEEP** (`[§3.6]`: tried and failed otherwise).
- **Synchronous kernel work kept, in program order:** a faulting block emits its
  executed prefix *at the fault*, the handler at its nesting depth, the remainder
  as a continuation of the same block after return — each piece declaring the
  range it is complete for. **KEEP** — reality + ACCURACY `[§3.6][arch]`.
- **Asynchronous interrupts excluded by default** (opt-in to trace). **KEEP** `[§3.6]`.

**Judgment tie-back.** The golden carries a label-stamp-at-promote apparatus
(`CstEmitLabel`) *because* it emits a dispatch late (Stage B). With in-instruction
capture, a record is tagged with the context it executed in, directly — so the
stamping apparatus is **changed out**, not reproduced. This is the same accuracy
change as B.3, seen from the identity side.

---

## G. RECORD MODEL and SERIALIZATION — separable, by instruction

**REALITY/INTENT `[§3.11]` + tester (e).** The *information* the trace carries and
the *bytes* it is written as are two different concerns. The recorder's job is the
information; writing it efficiently is a solved problem that a maintained library
should own.

**Mechanisms the tracer must have:**

- **A typed record model** — templates, per-invocation records (range, memops,
  register snapshots, resolved branch), wrong-path chains, context switches,
  profile — expressed independently of how bytes are laid down. Its invariants are
  reality's: **never serialise a value that was not observed; lose no information a
  microarchitecture needs** `[§3.9, fmt]`.
- **A pluggable serialization backend behind a seam (tester e).** The current
  hand-rolled `.cst` delta encoder — per-`(template,ins_pos,field)` overlays, a
  running FID cursor, an 8192-entry FID→slot LUT, a two-pass decoder — becomes
  *one* backend, kept as a reference/fallback. The assessed **primary is a
  database / columnar backend** (SQLite for streaming+indexed random access, or
  Parquet/Arrow for per-column compression and predicate pushdown), so size and
  read-efficiency are the library's job, not ours. **CHANGE** — this deletes most
  of the 4,853-line encoder; judged by the simplicity test, in service of the same
  correct record model.
- **Tester (c): the wrong-path layer is a lazy delta on top of the correct-path
  layer, separately decodable** — a consumer that does not model speculation never
  pays to parse it. Native under a columnar backend (a separate column group);
  under the custom backend it means hoisting WP out of the inline per-record
  framing. **CHANGE** `[§3.5]`.
- **Tester (a) resolves here too:** typed columns make the hot branch/ memop fields
  cheap without any FID-width game.
- **The async writer** (producer decoupled from the disk sink) stays under any
  backend, because a sink that blocks must not deform guest timing. **KEEP** `[arch]`.

---

## H. THE INSTRUMENT — what QEMU must expose, and when (derived)

Each need below is derived from a capture stage; the base must meet it. The
golden's existing base modifications are the **evidence** each is achievable and
the **anti-drop ledger** — enumerated in detail in `02a_qemu_interface.md`, which
this section governs (02a is re-headed to map each modification under the need it
serves, not to organise the layer). **None of this surface is dropped;** the one
*addition* is H.2.

1. **Decode facts, at translation** (for B.1): per-instruction src/dst sets,
   per-access provenance, fold notes, the resolved static branch target, the
   generic word — all from the target's own decode (`[qm]`: dataflow ABI,
   `branch_target_pc`). KEEP.
2. **Committed destination values + resolved direction + which fragment retired,
   at/after the instruction** (for B.3) — **the one new interface**, a
   post-retirement per-instruction delivery, so capture is in-instruction and the
   pending-seal defer is gone. Derived from ACCURACY, not copied. (Direction
   already delivered `[git:59f8101261]`; this adds the committed values and the
   executed-fragment fact.)
3. **Per-memop address/size/data at execution** (for B.3, B.4), incl. x86
   lazy-flags resolved for plugin reads and PAN-exempt debug reads for the gate —
   both golden correctness fixes `[qm]`. KEEP.
4. **A contained speculative mode + guest-time freeze + resync** (for E): spec
   mode begin/end, the spec store buffer + atomic shadow, `CF_FORCE_SLOW` /
   `TLB_FORCE_SLOW` containment, no-speculation-without-paging, device/global
   side-effect suppression, unsandboxable aborts, wrong-path syscalls
   fetched-never-performed, MOPS spec clamp, the vclock freeze +
   `spec_clock_resync` + vclock-agency, interrupt replay. KEEP — reality-forced
   (a real wrong path has no architectural effect) `[qm]`.
5. **Privilege / asid / thread-pointer / paging at execution** (for F), marker
   never-split, path-event causality for faults/async, VA TB identity under
   plugins, shutdown/reset close, disk-I/O ownership. KEEP `[qm]`.

Open interface assessment, flagged not decided: whether `CF_FORCE_SLOW` (x86
host) and the portable `TLB_FORCE_SLOW` unify behind one host-independent path.

---

## Ready for Layer 3

Every mechanism the tracer needs is introduced above and judged. Layer 3 specifies
the functions inside each block, and must close these derived-but-open points
against the code (read only to verify, never to source the design):

1. **B.3 / H.2** — the post-retirement delivery: does it remove the pending-seal
   defer entirely (both the destination-value and the executed-fragment facts), or
   only the register half; the shape is written to "entirely."
2. **D** — how far the dictionary's seven-map machinery collapses once the record
   model and the serialization backend own what reality does not force into
   separate maps.
3. **G** — which serialization backend wins a measured experiment (SQLite vs
   Parquet/Arrow vs the custom `.cst` fallback), on size / encode rate / decode
   cost / consumer ergonomics.
4. **H.4** — whether the two containment paths unify.

The judgments carry forward as this: **keep** = the golden records reality
correctly there; **change** = it does not (B.3 accuracy, E/G tester points, F
label apparatus) or carries complexity reality does not force (D maps, G encoder).
Nothing here is organised by the golden's structure; it is organised by what a
real machine does and what the intent records, which is the only thing this layer
is allowed to be.
