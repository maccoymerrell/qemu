What's in a ``.cst`` trace
==========================

This page is the "qualitative" answer to the question that the
:doc:`format` page answers byte-for-byte: what does a ChampSim Tracer
trace actually contain, and what kinds of research is it designed to
enable?  Read this before the wire-format spec if you're trying to
decide whether the tracer is the right tool for your work.

The high-level picture
----------------------

A ``.cst`` file is a basic-block-granularity execution trace plus a
deduplicated dictionary of every static basic block the program ever
ran.  Two halves:

**Templates** (the dictionary).  One entry per *true* basic block —
the run of architectural instructions from a branch target up to and
including the next branch.  Each template carries the static shape:
PC sequence, generic opcode, branch type, source / destination
register IDs, immediate, raw instruction bytes.  Templates are
shared across every dynamic invocation of that BB; if a hot loop
runs a million times the template is in the trace exactly once.
A template's true identity is its ``template_id``, not its
``start_pc``: self-modifying code that patches a block in place
mints a fresh template — a new ``template_id`` at the same
``start_pc`` — each time the correct path re-executes a changed
block, so a decoder resolves a block by the ``template_id`` a body
entry names, never by address alone (see :doc:`limitations`).  With
``static_templates=1`` (off by default) the dictionary also gains
never-executed entries: at every branch the correct or wrong path
evaluates, the plugin mints the untaken side's true BB if it isn't
already covered, giving a trace-inferred wrong-path consumer
fetch/decode coverage of code the traced execution itself never
reaches.  This coverage is convergent over the run rather than an
eager sweep of the binary's executable footprint (see
:doc:`limitations`).
Each template also carries a small **run-aggregated profile block**
— PGO-style metadata accumulated over the whole run (execution
counts, terminal-branch behaviour, per-instruction memory-access
shape).  It is pure annotation: it does not affect replay, and a
consumer that does not model PGO can discard it at decode.

**Body** (the timeline).  One record per dynamic invocation of a
basic block.  Each record points at a basic block by ID and adds the
runtime data: per-instruction memory addresses, optional data values,
optional destination-register data snapshots, and (when wrong-path
simulation is enabled) the speculative chain a mispredicting CPU
*would have* run from the just-finished branch.

Trace size on a measured workload — ``sha256sum`` over a fixed 5 MiB
input (14.5 M architectural instructions, x86_64), captured in three
plugin configurations and compressed with ``xz -T0``.  Numbers are
bytes per architectural instruction:

.. list-table::
   :header-rows: 1
   :widths: 50 16 16 18

   * - Configuration
     - Raw B/insn
     - xz B/insn
     - Ratio
   * - CP-only, addresses only
       (``wp=0,memdata=0``)
     - 0.234
     - 0.015
     - 15×
   * - CP+WP, addresses only
       (``wp=1,memdata=0``)
     - 1.23
     - 0.058
     - 21×
   * - CP+WP full
       (``wp=1,memdata=1,regdata=1``)
     - 7.62
     - 4.12
     - 1.8×

Compression ratio falls as more entropy is captured: the CP-only
trace is dominated by sparse delta records that compress well, while
memop addresses are nearly random and load / store / register values
are entropy-rich.  This workload is an extreme of that trend — its
full-capture register data is SHA hash state, near-incompressible, so
the full row compresses under 2×; a workload with lower-entropy
register values compresses several times better.  The :doc:`decoder`
``cst_audit`` tool breaks any trace down into this byte structure
exactly.

These numbers are workload-dependent.  Run ``cst_audit`` on a
representative slice of your own workload before sizing storage for a
long run.

What a body entry represents
----------------------------

One ``BODY_TAG_ENTRY`` is one *invocation* of one basic block on the
correct path.  Each body entry combines:

* The template ID (``BB`` number) that gives the static instruction
  sequence.
* Every per-instruction load and store address (and value, if
  ``memdata=1``) recorded between this BB's entry and its branch.
* The post-execution snapshot of every destination register written
  by this BB (if ``regdata=1``).
* The wrong-path chain: a sequence of speculative basic-block
  invocations the CPU would have run if its branch predictor had
  resolved the just-completed branch the other way.  Each WP entry
  has its own per-instruction memops and (optionally) its own
  destination-register snapshots.

Body entries are emitted in *correct-path execution order*.  The
trace is a faithful step-by-step record of the architectural
correct path, with speculative side-trips attached at every branch.

Run-aggregated profile (PGO metadata)
-------------------------------------

Every template carries a profile block summarizing what happened
across the *whole* run — final totals, serialized at segment
finish, never running snapshots.  It is the trace's built-in
profile-guided-optimization layer: a consumer can size structures
or pick policies from it without a separate profiling pass.  Pure
metadata — skipping it changes nothing about replay.

Per basic block:

* **Execution counts** — ``exec_cp`` / ``exec_wp``: how many times
  the BB ran on the correct and wrong paths.  ``0`` / ``0`` is
  valid: a REP string-op self-loop sub-template is pre-declared at
  translation but only emitted once the REP iterates twice or more,
  so a REP that never iterated leaves an unexercised 0/0 template.

* **Terminal-branch edges.**  Both edges of the BB's terminating
  branch are always known — the correct path supplies whichever it
  took, the wrong-path resolver supplies the other — so they are
  recorded even if the correct path never took the branch.  The
  not-taken edge is the template's ``fall_through_pc``.  The taken
  edge(s) are a per-BB target list: exactly one entry for a
  non-indirect branch (its single taken target, valid even on the
  wrong path since it is architecturally fixed); for an
  indirect / return branch, the set of distinct **correct-path**
  targets observed (wrong-path indirect targets depend on
  speculative register state and are deliberately excluded — they
  would poison the very pool the wrong-path resolver mines).

* **Per-target taken / not-taken counts** (CP and WP).  For a
  non-indirect branch this is the conditional's taken-vs-fall-
  through split; for an indirect branch the CP counts are per
  target.

* **Per-instruction memory shape.**  For each instruction:
  correct- and wrong-path mem-op counts, the effective-address
  range touched, a *data-is-address* flag (a loaded / stored value
  whose page a real correct-path mem-op also touched — a pointer-
  chasing signal), and an **access-pattern class** — one of
  ``regular``, ``irregular``, or ``random``.

  Each memop is classified individually and tallied into a
  per-instruction histogram; the reported class is the argmax bin
  — the regime the instruction spends most of its lifetime in.
  Two complementary tests run per memop:

  1. A **polynomial chain** in absolute-magnitude space — walk
     derivative levels :math:`0 \dots K-1` (where :math:`K =
     \texttt{CST\_PAT\_POLY\_DEPTH} = 4`).  Each level is the
     abs difference of the previous level: level 0 is
     :math:`|\Delta f|`, level 1 is :math:`||\Delta f|_n -
     |\Delta f|_{n-1}|`, and so on.  Convergence at level 0
     (``|delta_n| == |delta_{n-1}|``) tags the step ``regular``;
     convergence at any deeper level tags it ``irregular``.
     :math:`K = 4` covers polynomial address streams up to
     degree 4.  Absolute magnitudes prevent bounded-complexity
     patterns whose signed deltas oscillate (e.g. addresses
     ``0,1,3,4,6,7`` ⇒ deltas ``1,2,1,2,1`` ⇒ signed ddeltas
     ``+1,-1,+1,-1`` but ``|ddelta|=1`` everywhere) from being
     labelled higher-order than they structurally are.
  2. A **geometric rescue** — constant-ratio detection on the
     last three magnitudes at every level the polynomial walk
     descends past, using the exact-integer cross-multiply
     :math:`|x_n|\,|x_{n-2}| = |x_{n-1}|^2`.  Catches pure
     exponential patterns (e.g. ``2^n``-stride binary walks) and
     any polynomial-plus-exponential mixture up to polynomial
     degree :math:`K-2`: the polynomial part annihilates by
     some level and the exponential survives with a constant
     ratio.  Fires the rescue (overriding ``random`` to
     ``irregular``) only when the polynomial chain found no
     convergence.

  Two trackers contribute to the histogram in parallel — a
  per-insn classifier keyed by issuing PC, and a cross-instruction
  *spatial* classifier keyed by page (within-page offset deltas —
  picks up stencil sweeps where each insn looks chaotic but the
  basic block stripes a page linearly).  Each tracker takes its
  own argmax, and the emitted class is the lower (more regular)
  of the two.

The exact byte layout is in :doc:`format` (Step 4.6 / §6); the
:doc:`decoder` renders it inline per BB and ``cst_audit`` shows
how many trace bytes it costs.

System-mode traces
------------------

The tracer runs against both of QEMU's TCG emulators.  Under
``qemu-<isa>`` (user mode) the trace covers one process's user-space
execution; system-call boundaries appear as ``GEN_OP_SYSCALL``
instructions and kernel execution is invisible — user-mode QEMU passes
each syscall through to the host kernel, which services it outside the
guest.  Under ``qemu-system-<isa>`` QEMU emulates a whole guest OS; the
tracer targets one chosen process inside it, and the kernel becomes part
of the picture:

* **The window is guest-driven and marker-scoped.**  A process runs a
  magic marker instruction sequence at its entry; the plugin opens the
  trace window there and admits that process's address space to an
  owned-ASID set.  Under the default ``policy=latch`` every process
  that runs the START marker joins the set and is traced concurrently
  until its own END marker; ``policy=trace-all`` instead widens the
  first START to capture every context.  Each captured entry carries a
  ``(thread_id, asid)`` context — rebased by ``BODY_TAG_ASID_SWITCH``
  records — so a consumer can separate interleaved processes in the one
  body stream.  The window budget counts the *user-space* instructions
  of the marker process that pins the clock, so a system-mode window
  covers the same workload instructions a user-mode run would, with the
  kernel's contribution added rather than substituted.
* **Synchronous kernel code is first-class.**  The syscalls the
  workload makes and the fault handlers it triggers (page faults,
  TLB refills) are traced as ordinary basic blocks.  Kernel-context
  instructions carry the ``SYSTEM`` flag bit, so a consumer can
  model or filter them; entries executed inside a fault handler
  additionally carry the handler's nesting depth, and a faulting
  basic block appears once, whole, with its faulting instructions
  marked.  (See :doc:`format` for the flag bit and the per-entry
  fault trailer.)  Setting ``faults=0`` excludes the synchronous
  handler instead — the interrupted block still appears whole, but
  the handler excursion is suspended and the trace carries no anchors
  or nesting depth.
* **Asynchronous interrupts are excluded by default.**  Timer ticks,
  device IRQs, and the scheduling they trigger are OS noise
  uncorrelated with the traced workload, so the whole
  delivery-to-return excursion is left out of the trace.  Setting
  ``interrupts=1`` traces the handler instead — its kernel blocks
  appear at exception depth ``>= 1`` between the interrupted context's
  entries, attributed to the interrupted process — for a model that
  wants the asynchronous OS overhead too.
* **The wrong path crosses the privilege boundary.**  Speculative
  chains run through kernel code like any other, bounded by the
  same MMU rules a real speculative fetch obeys.

.. important::

   **Run system mode with kernel page-table isolation disabled**
   (``nopti`` / ``pti=off`` on x86, and the analogous
   page-table-isolation switch on other ISAs).  This is the canonical
   system-mode configuration.  With KPTI off the kernel lives in each
   process's page tables under that process's own address-space root,
   so the kernel *shares the process's ASID* — one address space per
   process, kernel included.  A kernel basic block is then tagged with
   the **owning process's** ASID (distinguished from user code by the
   per-insn ``SYSTEM`` bit), and the same kernel code at the same
   address is one template rather than one per process.

   OS-level isolation (KPTI and similar side-channel mitigations) is
   **modeled by the consumer**, not captured in the trace.  This is
   fully reconstructible: every block carries the ``SYSTEM`` bit, so
   kernel and user execution are exact, and kernel data pages never
   share virtual addresses with user pages — so a consumer can
   re-impose any isolation policy on the address stream without
   ambiguity.  Booting *with* KPTI enabled still produces a valid
   trace, but it bakes one specific mitigation configuration into the
   address stream (the isolated kernel root becomes visible) instead
   of leaving the consumer free to model it, and is not the supported
   baseline.

The mechanics — marker detection, the address-space pin, fault
excursions, async exclusion — are described in
:doc:`architecture`.

Research questions the trace is designed to answer
--------------------------------------------------

The trace is sized and shaped for cache-, branch-, and prefetcher-
research.  Specifically:

**Cache simulation.**  Each load and store in the body stream
carries its virtual address (``ld@`` / ``st@`` in the disasm dump),
and optionally the data value.  Drop the trace into a cache
simulator and you have a per-instruction reference stream.  The
wrong-path stream lets you study cache pollution from speculation:
what cache lines a mispredicting machine would have brought in and
later evicted.

**Branch prediction.**  Every branch instruction in the trace carries
a ``branch_type`` (direct / indirect jump, direct / indirect call,
return, conditional, syscall) and, on every branch-terminated block —
correct path and each wrong-path chain block — two always-present
singletons that give its dynamic outcome directly:
``CST_FID_BRANCH_TAKEN`` (taken vs fell through) and
``CST_FID_BRANCH_TARGET`` (the landing PC as a signed offset from the
branch), so a consumer recovers direction and target without decoding
ahead to the successor.  The wrong-path chain models which alternate
path a misprediction would have entered, bounded by ``wpdepth``
instructions.  Useful for predictor accuracy, branch-history length
studies, and BTB capacity work.

**Prefetcher evaluation.**  Software prefetch hints
(``GEN_OP_PREFETCH``) are surfaced as synthetic loads carrying
the prefetch target; cache-line clean / flush / invalidate ops
(``GEN_OP_CACHE_FLUSH``) and TLB-shootdown ops
(``GEN_OP_TLB_FLUSH``) similarly carry the addressed line.  A
prefetcher simulator gets address streams for both real demand
loads and the workload's prefetch hints in one place, plus a
wrong-path stream that exposes prefetcher-training behavior under
speculation.

**Value prediction.**  Pass ``regdata=1,memdata=1`` and every
destination-register write and every memop value lands in the
trace.  Value-prediction researchers can train and evaluate
predictors against the recorded post-execution values.

**Microarchitectural design-space exploration.**  The combination
of templates + dynamic memops + wrong-path chains is enough for
detailed simulators (ChampSim and similar) to model out-of-order
issue, BTB hits, branch prediction, cache pollution from speculation, 
and prefetcher training in one pass.

What the trace is *not* designed for
------------------------------------

A few categories the trace deliberately does not cover — see
:doc:`limitations` for the full list:

* **Whole-system behavior.**  A system-mode trace is marker-scoped:
  it captures the marker-owned process (or, under ``policy=trace-all``,
  every context) plus the kernel code they synchronously invoke, not
  processes that never run a marker, not asynchronous interrupt
  handling, and not the OS at large.  In a user-mode
  trace, kernel execution is invisible entirely — system-call
  boundaries appear as ``GEN_OP_SYSCALL`` instructions and nothing
  more.
* **Microarchitectural timing.**  The trace is a functional record
  of *what executed*, not a cycle-accurate description of *when*.
  Timing models live in the consumer simulator.
* **Branch nesting beyond the initial mispredict.**  The wrong-
  path chain follows a single mispredicted branch; subsequent
  branches inside the speculative window are followed in their
  statically-resolved direction without spawning further nested 
  wrong-path chains.  This matches what most cache- and 
  prefetcher-research workloads need; if your research depends 
  on multiple-mispredict speculation chains (e.g. transient-execution 
  side-channel work), the chain will under-cover that domain.

Reading on
----------

* :doc:`quickstart` — install, run, and read a trace.
* :doc:`format` — byte-for-byte wire format.
* :doc:`decoder` — the offline tools (``cst_decode``, ``cst_audit``).
* :doc:`reference` — symbolic IDs for opcode / branch type / register
  / field-id used inside the trace.
* :doc:`architecture` — internal design of the plugin.
* :doc:`limitations` — what the tracer doesn't do.
