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
Each template also carries a small **run-aggregated profile block**
— PGO-style metadata accumulated over the whole run (execution
counts, terminal-branch behaviour, per-instruction memory-access
shape).  It is pure annotation: a consumer that does not model it
skips the bytes.

**Body** (the timeline).  One record per dynamic invocation of a
basic block.  Each record points at a basic block by ID and adds the
runtime data: per-instruction memory addresses, optional data values,
optional destination-register data snapshots, and (when wrong-path
simulation is enabled) the speculative chain a mispredicting CPU
*would have* run from the just-finished branch.

Trace size on a measured workload — 20 M instructions of
``505.mcf_r`` and ``502.gcc_r`` (SPEC CPU2017 refrate input,
x86_64), each captured in three plugin configurations and
compressed in-process by the tracer with ``xz -T0 -q -c``.
Numbers are bytes per architectural instruction of the 20 M
window:

.. list-table::
   :header-rows: 1
   :widths: 38 12 16 16 18

   * - Configuration
     - Workload
     - Raw B/insn
     - xz B/insn
     - Ratio
   * - CP-only, addresses only
       (``wp=0,memdata=0``)
     - mcf
     - 1.83
     - 0.21
     - 8.9×
   * -
     - gcc
     - 2.00
     - 0.07
     - 27×
   * - CP+WP, addresses only
       (``wp=1,memdata=0,wp_memdata=0``)
     - mcf
     - 22.5
     - 2.29
     - 9.8×
   * -
     - gcc
     - 21.9
     - 0.88
     - 25×
   * - CP+WP full
       (``wp=1,memdata=1,regdata=1``)
     - mcf
     - 66.3
     - 7.94
     - 8.3×
   * -
     - gcc
     - 49.4
     - 4.52
     - 11×

Compression ratio falls as more entropy is captured: the CP-only
trace is dominated by sparse delta records that compress well,
while memop addresses are nearly random and load / store /
register values are entropy-rich.  The :doc:`decoder`
``cst_audit`` tool breaks any trace down into this byte
structure exactly.

These numbers are workload-dependent.  gcc has more BB diversity
and more conditional flow than mcf but a smaller and more
repetitive memory footprint, so its CP-only trace compresses 3×
better despite being slightly larger raw.  mcf's heavy random-
ish memory traffic inflates the CP+WP-full configuration and
caps its compression ratio around 8×.  Run ``cst_audit`` on a
representative slice of your own workload before sizing storage
for a long run.

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

**Branch prediction.**  Every branch instruction in the trace has
both a ``branch_type`` (direct / indirect / return / cond /
syscall) and the actual outcome (which template the next body
entry references).  The wrong-path chain models which alternate
path a misprediction would have entered, bounded by ``wpdepth``
instructions.  Useful for predictor accuracy, branch-history
length studies, and BTB capacity work.

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

* **Kernel behavior.**  The plugin runs only against QEMU's
  user-mode emulators.  System-call boundaries appear in the trace
  as ``GEN_OP_SYSCALL`` instructions, but the trace does not see
  inside the kernel.
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
