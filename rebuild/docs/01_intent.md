# ChampSim Tracer — Layer 1: INTENT

*The design of record for the fresh rebuild, layer 1 of 3. This layer says
**why** every part of the tracer exists and what it must preserve. It says
nothing about **how** — module shape is Layer 2, function behaviour is Layer 3.
It is written small on purpose: it rides in **every dispatched agent's context
at all times**, so that no line of the rebuild is ever written without its
intent in view. That omission — writing code and docs with the mechanism in
hand but the intent out of view — is the single flaw that voided the last four
rebuilds. When this layer reaches the writing phase, the golden tracer's **code**
is closed to the author and the plan is the only source — the rule drilled in the
non-negotiables below and in §4.8.*

Each claim carries a bracket receipt to its authoritative source:
`[purpose]` = the maintainer's purpose statement (below); `[concepts]`,
`[limits]`, `[arch]`, `[quickstart]`, `[format]` = the doc tree under
`contrib/plugins/champsim_tracer/docs/`; `[rule]` = a standing maintainer
ruling. Where a source is cited the rebuild agent may and should go read it.

---

## Non-negotiables — drilled on purpose, never discarded

These rules recur throughout this document **by design**. They are repeated in
their own sections so that an agent who reads only part of this file still meets
them, and so none can be quietly dropped. If you internalise nothing else,
internalise these:

1. **Model reality.** Every emitted line is what a real processor physically does
   executing these instructions. `[rule]` (§1)
2. **Derive from QEMU; never a second decoder.** Zero Capstone inside the tracer —
   what the emulator refuses to execute is what the tracer refuses to record.
   `[rule]` (§3.1)
3. **Do not read the golden tracer's CODE while writing.** The plan is the sole
   source; a felt need to peek is a gap in the plan, to be filled in the plan.
   `[rule]` (§4.8)
4. **System mode is pervasive** — identity, faults, interrupts, privilege and
   strands are designed in from the start, never bolted on. `[rule]` (§3.6)
5. **Classify every instruction reachable in QEMU.** A probe fault is never proof
   of non-reachability. `[purpose]` (§0)
6. **Correctness beats the golden tracer.** Golden is a flawed reference, not an
   oracle; adjudicate a deviation on correctness. `[rule]` (§1)
7. **Clean rewrite, not patch.** Tear out the affected region and rebuild it from
   this intent. `[rule]` (§4.5)
8. **Lose no real information** a microarchitecture needs; no pessimistic discount
   stands in for a real edge. `[rule]` (§4.6)

---

## 0. The purpose — outranks everything

Nothing in the rebuild outranks these words. Not code, not a doc, not a comment,
not this file. `[purpose, 2026-09-22]`

> The purpose of the tracer is to trace qemu execution on the 4 target ISAs for
> both correct and wrong-path. The information recorded for each instruction are
> those necessary to simulate the microarchitecture of a machine executing said
> instructions: opcode, registers, memops, and the natural requirements of those
> (reg data, mem data, mem addresses) as well as information necessary for proper
> microarchitectural simulation (intra-instruction dependencies, vector lanes,
> memop->lane mappings).

Two corollaries follow directly and are binding: **every instruction reachable
in QEMU must be classified** — a probe-environment fault (bad operands, probe
state) is the probe's fault and never proof of non-reachability; and when a
design question arises, **derive the answer from this statement before asking**,
because every ruling so far has been derivable from it. `[purpose]`

## 1. Reality is the ground

The tracer models **what a real processor physically does** on every line it
emits. `[rule, 2026-11-01]`

- **QEMU is the instrument**, the authoritative witness of what executes — not a
  thing to be second-guessed by another decoder. Information about an
  instruction is *derived from QEMU's own behaviour and narrow exposure*, never
  re-derived by a parallel decoder reading the same bytes. `[rule][arch: qdep,
  vocabulary]`
- **The golden tracer is a flawed reference**, not an oracle. Byte-identity to
  it is a *check*, not the goal. Where the golden deviates from reality, the
  rebuild does the correct thing and the deviation is adjudicated a golden bug.
  `[rule, 2026-10-31]`
- **The one carve-out from "model reality":** never bake in microarchitectural
  *policy*. The wrong path is a single, execution-resolved direction — no branch
  predictor, no BTB, no replacement policy. Those belong to the consumer's
  simulator, which this trace feeds. `[rule][concepts][limits]`

## 2. What the trace is for — the consumer

The trace exists to drive a **microarchitectural simulator** (ChampSim and
peers): cache, branch-prediction, prefetcher, value-prediction, and OoO
design-space work. `[index][concepts]` It records *what* executed in
**commit order**, never *when* — there is no timing, IPC, or pipeline state in
the trace; timing lives in the consumer. `[index][concepts: "not designed for"]`
So every design choice is judged by one question: **does a real
microarchitecture executing these instructions need this information, and is it
here, faithfully?**

## 3. The intent of each part

### 3.1 Classification / decode — from QEMU, zero Capstone in the tracer
Each instruction's opcode (a portable generic word), its register sets, its
per-access provenance, and its fold notes are **read from QEMU's own decode
rules** through the dataflow plugin ABI, and joined against one small
vocabulary table. The tracer consults **no second decoder**: what the emulator
refuses to execute is exactly what the tracer refuses to record. `[arch: qdep,
vocabulary][quickstart]` Capstone appears **only offline**, in the acceptance
referee (`tools/cst_referee.py`), through the Python bindings, scoring a trace
after the fact — it never reaches the wire. `[CLAUDE.md][rule]`

### 3.2 Templates (the dictionary) and body (the timeline)
A `.cst` trace has two halves. **Templates** = a deduplicated dictionary of
every *true basic block* the program ran (branch target → next branch): the
static shape (PC sequence, generic opcode, branch type, src/dst register IDs,
immediate, raw bytes), plus a pure-annotation run-aggregated profile block a
consumer may discard. **Body** = one record per dynamic invocation, keyed to a
template, carrying the runtime data. `[concepts][index]` A template's identity
is its `template_id`, **never its `start_pc`** — self-modifying code mints a new
revision at the same address, and a decoder resolves by id. `[concepts][limits:
SMC]` The dictionary is what keeps a million-iteration loop one template.

### 3.3 Memory operands
Every load and store carries its **effective address**; with data capture on,
its **value**; always its **size**. Addresses and sizes are always recorded even
when a wide value cannot be. `[concepts][limits: mem-value-width]` Software
prefetch, addressed cache-line ops, and TLB-shootdowns carry a *synthesized* EA
so a prefetcher model sees them alongside the real demand stream. `[concepts:
prefetcher][arch: synthetic EA]` An instruction with unbounded, register-sized
memory fan-out (x86 `REP`, AArch64 FEAT_MOPS) is rendered **one access per body
entry** (a synthetic 1-insn self-loop), so no slot table is ever overrun.
`[arch: self-loop][limits: bulk-memory]`

### 3.4 Dataflow dependencies and vector lanes
The trace carries the **intra-instruction dependencies** and the **vector lane**
structure a real OoO machine needs: per-instruction src/dst register sets, and
per-memop → per-lane mappings. The register ID space is *generic*, and two
architectural registers share one generic ID **exactly when a consumer ordering
one against the other is right, and get separate IDs when it is not** — a false
dependency edge costs a consumer as much as a missing one. `[arch: sysreg
operands][reference]` The **lane-mask model is required**: four dynamic
per-slot classes (src / dst / load / store); the opcode `kind` only says *where
to read*, the actual mask is computed from the operand/memop layout.
`[rule][limits: RVV/SVE lanes]` A refiner's precision is justified only when it
**enables modelling a real CPU optimization**, never precision for its own sake.
`[rule]`

### 3.5 Branches and the wrong path — a fetch phenomenon
Every branch-terminated block carries its **resolved direction and target**
directly (taken-vs-fell-through and the landing PC), on the correct path and on
every wrong-path block. `[concepts: branch prediction][format]` The **wrong
path** models what a mispredicting frontend *would have fetched*: a single
execution-resolved alternate direction, bounded by `wpdepth` instructions, which
**walks past** a speculatively-fetched syscall/trap at its fall-through (a real
frontend fetches around one and squashes it at retire) rather than stopping.
`[concepts][limits][arch: wp-termination]` A wrong path physically **stops**
only for a real fetch reason: budget exhausted, or an instruction-fetch the
guest MMU cannot translate — never for a host-instrument limit. Wrong-path
*control flow and addresses* are exact; wrong-path *instruction identity* down an
arbitrary byte stream is best-effort by design. `[arch: wp-termination][limits]`

### 3.6 System mode — pervasive, not a late add-on
Under `*-softmmu` the tracer targets **one real process inside a whole guest
OS**, and the kernel becomes part of the picture. This is first-class and
touches nearly every part of the tracer; it is **not** bloat and **not**
deferrable. `[rule][concepts: system-mode][arch: system-mode]`
- **Identity is content-at-vaddr, and only that.** At every committed
  address-space change the tracer re-reads the marker sequence's bytes at each
  latched window vaddr through the live context; a context that maps them is
  traced. **No page-table root, ASID, or process id is ever stored or compared
  as an identity** — that was tried repeatedly and failed; content-at-vaddr is
  the mechanism that holds. There is no recycling exposure, no re-bind rule, no
  proof-of-life probe. `[rule, G-CORRECTION][limits: content-at-vaddr][arch:
  cp-flow gate]`
- **Synchronous kernel code is kept and first-class.** Syscalls and fault
  handlers (page faults, TLB refills) trace as ordinary blocks at their
  exception-nesting depth; a block a fault interrupts emits its executed prefix
  **at the fault**, in program order, and its remainder as a continuation of the
  same template, each piece declaring the range it is complete for. `[concepts]
  [arch: fault-excursions]`
- **Asynchronous interrupts are excluded by default** as OS noise uncorrelated
  with the workload (opt-in with `interrupts=1`). `[concepts][arch:
  async-exclusion]`
- **Privilege and strand.** Every record carries `(thread_id, asid)` and a
  per-insn `SYSTEM` bit; `thread_id` is a **guest-thread identity, never a vCPU
  id**, stable across vCPU migration, read from the guest kernel's own
  per-thread pointer. KPTI-off is the canonical configuration (kernel shares the
  process's ASID). `[arch: multi-vCPU, single-address-space][concepts:
  KPTI][limits: kernel-strand]`
- **The wrong path crosses the privilege boundary** under the same MMU rules a
  real speculative fetch obeys. `[concepts]`

### 3.7 User interaction — the shape, and why it is shaped so
The user picks exactly one **window mode**, and the shape is justified by what a
researcher actually captures. `[quickstart: segmentation]`
- **SimPoint is the defining use case:** one pass over a loaded simpoint file
  produces **one stand-alone, self-contained `.cst` per simpoint** — own header,
  own templates dictionary, own body — carrying nothing from a prior region. A
  region's trace is byte-identical whether traced alone or as one of N.
  `[rule][quickstart: simpoint][concepts]`
- **User mode** also offers `icount` (a start/stop window), `symbol`
  (Nth occurrence), and `marker`.
- **System mode requires a marker.** A clock (icount/symbol/simpoint) can
  position *when* but cannot say *whose* instructions it counts, so under
  `*-softmmu` a bare clock window is **refused at install**; a SimPoint schedule
  is *composed onto* a marker (`marker:...+simpoints=...`), the marker supplying
  the anchor and the offsets positioning on the pinned process's user-instruction
  clock. `[rule][quickstart: marker-window, marker-simpoints][arch: asid-pin]`
- A system run must be able to **end**: an END marker, a guest shutdown, a
  dead-latch backstop, or a stall ceiling. A run that cannot end is refused.
  `[quickstart: stall_ceiling_any]`

### 3.8 Time transparency
The tracer is an instrument on the vCPU thread, **not part of the machine**. Its
host wall-clock cost is never charged to guest time: correct-path
instrumentation and the entire wrong-path excursion run with the guest virtual
clock frozen and every architectural clock/timer/interrupt-line resynchronised to
the frozen time on exit. A wrong path consumes **exactly zero guest time**, so
speculation depth is a modelling choice, not a budget. **Time is never offered
as the cause** of a guest that stops progressing — a frozen clock cannot be
starved by host time; such a case is a state defect on the WP restore.
`[limits: wp-transparency][arch: time-transparency][rule]`

### 3.9 Determinism and faithful capture
The trace records what the guest did; anything the guest can read that differs
run-to-run comes back as a difference. With the byte-stability breakers pinned
(ASLR, kernel randomness, process identity, host scheduling, inherited
environment), a single-vCPU user-mode trace is bit-deterministic, wrong path
included. A guest cycle/time read is **inside** the pin: while a plugin is
loaded QEMU serves a deterministic per-vCPU tick, not the host oscillator.
`[limits: reproducibility][rule]`

### 3.10 Deliberate bounds
A small set of fixed ceilings are **chosen contracts**, not accidents, and the
rebuild preserves them as such: 512 slots per direction per instruction
(`CST_FID_SLOT_COUNT`), 64-byte (512-bit) value/register-snapshot width
(`CST_MAX_WIDE_BYTES`), 255 generic register IDs, the `MO_128` value read-back
limit, and the documented modelling limits (SME accumulator, SVE predicate
*value*, FPSR/`fflags` accumulation, RVV `vstart`/tail-undisturbed). Each is
documented with the consequence of hitting it; none is to be silently widened or
removed. `[limits: hard bounds, decode-metadata bounds]`

### 3.11 Offline tools, external referee, validator
The trace is scored and read by programs that run **after** it is written, never
in-process: `cst_decode` (disassembly dump), `cst_audit` (byte-budget
breakdown), `cst_visualize` (metric charts); the Capstone/LLVM-backed referee;
and the seed-driven multi-ISA validator that is the primary regression suite.
**Comparison is external** — reference decoders run offline over recorded bytes.
`[index][quickstart][rule: external comparison]`

## 4. Binding principles (carry these, lose nothing)

1. **Reality is the ground;** QEMU is the instrument; the golden tracer is a
   flawed reference and **correctness beats golden**. `[rule]`
2. **Derive from QEMU's behaviour**, never from a parallel decoder or from
   derivation inside the translators — derivation in the translators is the
   violation the rebuild exists to remove. `[rule: intended-architecture]`
3. **Every instruction reachable in QEMU is classified.** A probe fault is never
   proof of non-reachability. `[purpose]`
4. **System mode is pervasive.** Identity (content-at-vaddr), faults,
   interrupts, privilege and strands touch nearly everything; design them in
   from the start, never bolt them on. `[rule]`
5. **Clean rewrite, not patch.** Each fix is a tear-out-and-rebuild of the
   affected region from this intent, never an incremental patch-to-perfect loop;
   change the QEMU plugin interface where that simplifies the plugin side.
   `[rule, 2026-11-01]`
6. **No information loss.** Real information a microarchitecture needs is never
   dropped; no pessimistic discount stands in for a real edge. `[rule: R12.1]`
7. **The wire is the spec,** matched to the golden's output except where a golden
   deviation is adjudicated a bug; the wire never fabricates a value it did not
   observe (an unresolved branch is declared unresolved, never guessed).
   `[rule: wire-parity][format]`
8. **Do not read the golden tracer's code while writing — drilled.** This is the
   rule the rebuild exists to enforce, so it is stated plainly, and more than
   once. **Two phases, one boundary:**
   - *Planning* (writing these docs): reading the golden tracer **to ground the
     plan** is allowed, and so are the golden's git **commit messages** (the *why*
     behind a line). The authoritative **docs** under
     `contrib/plugins/champsim_tracer/docs/` are the design of record and are
     **always** readable, in every phase.
   - *Writing* (producing rebuild code): reading **or** copying the golden
     tracer's **code** — the plugin's `.cc`/`.h`, the offline tools' source, any
     golden-producing source — is **FORBIDDEN**. The plan (Layers 1–3) is the sole
     source. A felt need to peek is a **gap in the plan**, to be filled in the
     plan, never a licence to open the file.

   The golden was produced by a patch-to-perfect loop and that is how it became
   the monster; copying its code re-imports exactly what this rebuild is built to
   leave behind. The boundary is on the golden *code*, never on the *docs* or the
   *intent*. `[rule, 2026-10-29][rule: seal-scope 2026-10-29]`

## 5. Receipts and open reconciliations

**Distilled from** (read in full for this layer): the purpose statement
(`CLAUDE.md`); `docs/index.rst`, `concepts.rst`, `limitations.rst`,
`architecture.rst`, and the user-interaction half of `quickstart.rst`. Layers 2
and 3 additionally require `format.rst`, `reference.rst`, `decoder.rst`,
`validator.rst`, `extending.rst`, and `qemu_modifications.rst`, read when those
layers are built.

**Doc inconsistencies found while grounding this layer** (to reconcile, not
propagate): `limitations.rst` still contains two paragraphs ("Decode-metadata
bounds" and "Wrong-path decode of arbitrary bytes") that describe Capstone as
the *in-tree* decoder feeding operand metadata — stale against `CLAUDE.md`, the
`architecture` subsystem map (`qdep`: "Nothing here consults a second decoder"),
and `quickstart` ("Capstone: not used"). This INTENT follows the current ruling:
**classification is QEMU-derived; Capstone is the offline referee only** (§3.1,
§3.11). The rebuild's own docs must not carry the stale framing forward.

**Companion layers (planned, this same design of record).** Layer 2
(`02_shape.md`) is the block diagram — the modules, what each needs from QEMU,
where, and when. Layer 3 (`03_plan.md`) is the per-function behaviour, detailed
enough that even a weak model implements it correctly. Alongside them: a
**validation** doc (the external and current reference sources — gem5, PIN, Spike,
Capstone, LLVM, and the golden tracer — and how each stage is checked), and a
**lessons** doc recording the major issues the last attempt hit. The lessons doc
**enumerates every golden-tracer bug we discovered, each with its git receipt and
its status in the golden tree itself** — fixed in golden, versus only patched in
the thing being built while golden still carries it — so no known golden bug is
silently dropped or resurfaces later. `[rule, maintainer 2026-11-01]`
