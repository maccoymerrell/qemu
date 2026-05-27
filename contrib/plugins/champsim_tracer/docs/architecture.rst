Architecture
============

.. index::
   single: architecture
   single: CP path
   single: WP path
   single: BBTemplate
   single: scoreboard
   single: exec_lock
   single: thread_id
   single: per-thread FieldStateTable
   single: BODY_TAG_REGFILE; per-thread regfile
   single: speculative store buffer
   single: vcpu_tb_exec
   single: vcpu_tb_trans

This page describes how ChampSim Tracer is organized, the two main flow
loops (CP and WP), and the caveats every prospective modifier needs
to know.

Performance and overhead
------------------------

Where the runtime goes
~~~~~~~~~~~~~~~~~~~~~~

The tracer's hot path runs every architectural instruction through
three layers in series:

1. **TCG translation** (once per TB, on first sight).  The tracer
   asks Capstone for instruction-detail metadata via
   ``qemu_plugin_insn_detail`` and walks the per-ISA classification
   table.  Cost is paid once per static basic block, so it amortises
   to a negligible fraction of total runtime on long workloads.
2. **CP attribution** (every TB execute).  ``vcpu_tb_exec`` walks
   the previous TB's instruction list, bumps stats, drains the
   per-thread memop accumulator, and folds the just-finished
   fragment into the in-flight chain.  Holds ``exec_lock`` and a
   short ``data_lock`` window for the BB cache writes.
3. **WP simulation** (when ``wp=1`` and the TB ends in a branch).
   Saves CPU state, flips the per-vCPU
   ``cpu->plugin_spec_mode`` flag, runs ``cpu_plugin_exec_tb`` in
   a loop until the depth budget exhausts, then restores.  The
   cost is roughly proportional to ``wpdepth`` instructions of
   speculative execution per branch.

The numbers below are measured on the SPEC CPU2017 ``mcf_r``
refrate input, 20 M architectural instructions of capture
(x86_64 host, gcc 13).  They are representative of this workload
only; other workloads vary in both runtime and trace size.
Sizes are MiB; compressed sizes come from recompressing the raw
body+header pair with ``xz -T0`` (the tracer's default in-process
compressor when ``compress=`` is set).

.. list-table::
   :header-rows: 1
   :widths: 38 12 12 12 12 14

   * - Configuration
     - Wall (s)
     - Raw size
     - xz size
     - B/insn raw
     - Slowdown
   * - stoptrigger only (no recording)
     - 0.18
     - n/a
     - n/a
     - n/a
     - 1× (baseline)
   * - ``wp=0,memdata=0,regdata=0``
     - 3.2
     - 19.4 MiB
     - 0.15 MiB
     - 1.0
     - 18×
   * - ``wp=1,memdata=0,regdata=0``
     - 60.4
     - 272 MiB
     - 2.4 MiB
     - 14
     - 335×
   * - ``wp=1,memdata=1,regdata=0,wp_memdata=0``
     - 63.6
     - 281 MiB
     - 3.0 MiB
     - 15
     - 353×
   * - ``wp=1,memdata=1,regdata=1``
     - 109.2
     - 623 MiB
     - 18.8 MiB
     - 33
     - 607×

Reading the table:

* **Slowdown vs the stoptrigger plugin** (which is roughly
  unmodified-QEMU runtime): tracing without WP costs ~18× on this
  workload because every TB pays a ``vcpu_tb_exec`` callback +
  Capstone-classification + chain-assembly walk.  Enabling
  WP simulation jumps to several-hundred× because every CP branch
  triggers a separate TCG re-entry for the speculative side-trip.
  Adding ``regdata=1`` is a further ~1.8× on top — every
  instruction's destination registers are read out via
  ``qemu_plugin_read_register``.
* **Trace size:** the field-delta encoder is highly compression-
  friendly.  CP-only addresses produce ~1 byte/insn raw and
  compress to under a hundredth of a byte each.  The full
  configuration (CP+WP, all data, all reg snaps) lands near
  33 bytes/insn raw, compressing to ~1 byte/insn.  The recent
  encoder optimisations (per-template field-state cache, inlined
  field-delta emit loop) account for the gap vs. older numbers in
  the public small-trace bundle.
* **Memory footprint:** the plugin's RSS grows roughly with the
  template-cache size (one ``BBTemplate`` per static basic block,
  on the order of a few hundred bytes each) plus the WP simulator's
  speculative-store buffer (bounded by ``wpdepth`` × the workload's
  store rate).  Peak RSS on this 20 M run was ~320 MiB with
  ``wp=0,memdata=0`` and ~1.25 GiB with full capture.

Workload-dependence caveat: mcf has a tight inner loop that delta-
encodes well.  Branch-heavy workloads (e.g. SPEC ``perlbench``)
push more bytes per instruction; memory-bound workloads with
diverse access patterns inflate the data-bearing configurations
further.  Run ``cst_audit`` on a representative slice of your own
workload before sizing storage for a long run.

How to measure
~~~~~~~~~~~~~~

Three tools, each answering a different question:

* ``cst_audit trace.cst`` — exact byte breakdown of where the
  trace's bytes went.  Use to diagnose which configuration knob
  has the biggest effect on size.  See :doc:`decoder`.
* The exit-time stderr summary — printed by every plugin run,
  contains CP/WP totals, branch-type breakdown, opcode usage, and
  per-segment timing.  Useful for runtime + opcode-mix sanity.
* ``time qemu-x86_64 -plugin ...`` — runtime vs the same QEMU
  invocation without ``-plugin``.  The slowdown ratio is a
  reasonable proxy for the plugin's per-instruction cost.

Mitigations
~~~~~~~~~~~

If trace size or runtime is a problem:

* **``simpoint`` mode** carves a long workload into representative
  segments rather than tracing it whole.  Combine with
  ``warmup=N,simulation=N`` to control segment length precisely.
* **``compress="xz -T0 -q -c"``** or
  ``compress="zstd -T0 -19 -q -c"`` runs the compressor in-process
  so each member inside the ``.cst`` archive lands compressed.
  The wire format's delta encoding leaves long runs of small bytes
  that both compressors handle well — measured ratios on the mcf
  workload above range from ~33× (full data) to ~129× (CP-only
  addresses) under default ``xz -T0``.  ``zstd -19`` lands at
  similar ratios on this data (within ~10 %).  The in-memory trace
  size is unchanged but the on-disk footprint shrinks substantially.
* **``wp_memdata=0``** keeps the WP cache-pollution stream
  (addresses) but drops the WP data values.  This is usually the
  biggest single trace-size knob.
* **``wp=0``** if the consumer doesn't model speculation.

Hot-path micro-optimisations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The encoder and per-callback paths carry several non-obvious
optimisations.  Each addresses a profiled hot spot, and the simpler
form it replaces measurably regresses; the entries below are
load-bearing:

* **TLS access cost.**  The plugin is ``dlopen``'d, so every
  ``thread_local`` access (``g_wp_state``, the ``g_stats`` macro)
  resolves through ``__tls_get_addr`` under the general-dynamic TLS
  model — a measured ~10 ns each, ~3 % of runtime, dominated by the
  per-memop callback.  Hot paths cache the TLS slot in a local once
  before loops / critical sections rather than re-touching it.
* **``RawBuf`` instead of ``GByteArray``.**  The per-entry encoder
  scratch uses an inlined-append ``RawBuf``.  ``g_byte_array_append``
  costs a glib call per ULEB byte, a measured ~1.5 % of total
  runtime.  ``RawBuf`` capacity grows 2× and never shrinks, so the
  scratch settles at the largest size any entry needed.
* **Field-state cache indexed by ``template_id``.**  A flat vector
  keyed by the dense ``template_id`` replaces a per-entry glib hash
  lookup; the hash lookup measures ~10 % on mcf.
* **``field_id`` to slot via a 1024-entry LUT.**  The LUT replaces an
  eight-branch chain that measures ~2.6 % at ~80 M calls.
* **``template_static`` skip.**  Instruction-encoding families
  (opcode, branch type, insn bytes, flags, immediate, size) equal
  their template default for every entry, so they never emit a
  record.  Skipping the probe entirely removes a cost that measures
  ~50 % of per-slot work on full-config mcf.
* **Narrow vs wide value paths.**  Families whose value fits in
  ``u64`` (counts, addresses, encoding fields, lane masks) compare
  two ``u64`` s in registers and only materialise a 512-bit value
  when the field actually changed; only ``LOAD_DATA`` /
  ``STORE_DATA`` / ``DST_REG`` take the genuinely-wide path.
* **Reg-handle pointer cache.**  A direct-mapped TLS cache keyed by
  ``QemuRegKey*`` identity (one stable instance per template
  reg-name) skips a glib-hash + ``strcmp`` chain that measures ~7–9 %
  on register-heavy workloads with ``regdata=1``.

Each entry is code whose simpler form costs the percentage stated; a
change to any of them is sound only when re-profiling shows the cost
has moved.

.. _multi-vcpu:

Multi-vCPU semantics
--------------------

QEMU's user-mode emulator handles multi-threaded guest workloads by
giving each guest thread its own host thread; each host thread
serves as a "vCPU" from the plugin's perspective.  The tracer is
designed for these multi-vCPU runs but enforces a serialized view of
the trace stream:

* **One body stream per segment, interleaved across vCPUs.**  All
  vCPUs share a single ``.cst`` file.  The body stream is a
  serialized interleaving of the basic blocks each vCPU ran, in
  the order ``vcpu_tb_exec`` callbacks fired across the host
  process.  Each ENTRY record is tagged with a
  ``thread_id`` (set by the most recent ``BODY_TAG_THREAD_SWITCH``)
  so consumers can reconstruct per-vCPU sub-streams by filtering.
* **``thread_id`` is the guest vCPU index, verbatim.**  Each ENTRY
  records ``cpu_index`` directly as its ``thread_id`` — there is no
  remapping table and no per-segment renumbering, so the value is
  stable for the whole run.  Each segment's body opens with an
  explicit ``BODY_TAG_THREAD_SWITCH`` naming the starting thread;
  there is no per-segment thread state to reset.
* **``icount`` is per-vCPU.**  The plugin maintains one instruction
  counter per QEMU vCPU.  Segment-window comparisons (``start=N``
  / ``stop=N``, simpoint windows) consult the firing vCPU's
  counter.  This means the segment window opens / closes when
  *any* vCPU crosses the threshold, not when the cross-vCPU sum
  does.
* **``exec_lock`` serializes the trace.**  Multiple vCPUs running
  concurrently on the host serialize through the plugin's
  ``exec_lock`` mutex inside ``vcpu_tb_exec``.  This guarantees
  the trace's body stream is well-ordered (each ENTRY corresponds
  to exactly one vCPU's BB execution) at the cost of removing
  parallelism among vCPUs while in the plugin.  For multi-
  threaded workloads this typically caps the tracer at ~1 vCPU's
  worth of parallel throughput; the QEMU runtime itself is still
  multi-threaded but the plugin callbacks are serialized.

Practical implications:

* **Lockstep guest behavior is preserved.**  Memory ordering as
  observed by each vCPU is faithful — each load/store appears in
  the trace with the value the running architecture would have
  read/written.  But the *interleaving* among vCPUs may differ
  from a native multi-core run because the plugin's lock perturbs
  scheduling.
* **Non-determinism across runs is normal on SMP workloads.**
  The tracer faithfully records whichever interleaving QEMU
  produced; pin the workload to a single host CPU
  (``taskset -c 0``) to reduce the variability of
  inherently-concurrent applications.
* **Sub-segment thread switches are sparse.**  ``BODY_TAG_THREAD_SWITCH``
  records are emitted only when the firing vCPU differs from the
  previous body record's vCPU.  Single-threaded workloads pay
  zero per-block thread-id overhead.
* **Field-state delta encoding is per-thread.**  Each
  thread maintains its own ``FieldStateTable``, so an ENTRY's
  delta-stream values are computed against the firing thread's
  prior emission rather than the cross-thread sequence.  This
  keeps delta compression effective on multi-vCPU workloads: a
  thread switch between two unrelated BBs does not force every
  per-instruction field to re-encode against the other thread's
  residual state.
* **Initial register files ride with the body stream.**  Before a
  thread's first ``BODY_TAG_ENTRY`` in a segment, the writer emits
  a ``BODY_TAG_REGFILE`` record carrying that thread's full
  register file as absolute values.  The header's encoding map
  carries no initial-regfile blob; the body-stream record
  represents threads that come online mid-segment, which a
  header-resident blob bound to the install-time vCPU cannot.

.. _tb-vs-true-bb:

Translation blocks (TBs) vs true basic blocks (true BBs)
--------------------------------------------------------

Two block flavours appear throughout this codebase, and they are
*not* interchangeable.

**Translation block (TB)** is QEMU's unit of translation.  When TCG
encounters a guest PC it hasn't translated yet, it emits a single TB
covering the run of instructions starting there until it hits an
artificial stop condition: a branch, an instruction-count limit, a
page boundary, a side-exit hint, or simply a TCG ``goto_tb`` chain
break.  TBs are *not* basic blocks — a single architectural basic
block can be split across two or more TBs (the most common cause is
the page-boundary check), and the same QEMU TB can also contain
*more than one* basic block when TCG keeps translating past an
instruction the plugin classifies as a branch terminator (the
canonical example is a MIPS conditional trap such as ``teq`` /
``tgeu``: TCG treats it as a conditional fall-through and continues,
while the trace must terminate a true BB at that instruction).
TBs are keyed in QEMU's translation cache by
``(pc, cs_base, flags, cflags)`` so the same code at the same PC can
have multiple distinct translations alive at once.  The plugin sees
one TB per ``vcpu_tb_trans`` callback, with one ``vcpu_tb_exec`` per
execution.

The translation-time **fragment splitter**
(``split_tb_into_fragments``) reconciles the TCG-vs-tracer
disagreement by partitioning the TB's canonical instruction stream at
every non-final branch terminator.  A TB containing no mid-TB branch
yields one fragment; a TB containing N mid-TB branches yields N+1
fragments.  Each fragment is its own ``BBTemplate`` with its own
``start_pc`` and one of three ``TbTerminus`` classes: ``COMPLETE``
(self-contained, branch + delay-slot pair entirely in this fragment),
``BARE_BRANCH`` (delay-slot ISA branch as the literal last
instruction; its slot lives in the next QEMU TB), or ``NONE``
(continuation fragment with no terminator).  Fragments produced from
one QEMU TB are linked into a singly-linked list via
``next_tb_fragment``; the per-TB exec-cb ``udata`` points at the head
of the list, and both the correct-path walker
(``vcpu_tb_exec``) and the wrong-path walker (``simulate_wrong_path_ext``)
iterate the list to find the fragments that actually executed in
this TB exec.  Templates produced by the splitter are owned by
``tb_templates_`` (a vector — *not* a start_pc-keyed map; sibling
translations of the same start_pc each get their own list and never
conflate).

**True basic block (true BB)** is the program-architectural unit:
the run of instructions from a branch target up to and including the
next branch, with no internal control-flow joins or splits.  A true
BB is what the trace's templates section dumps and what every body
``ENTRY`` record references.  The plugin builds true BBs at runtime
inside ``BBChainAssembler``: each ``vcpu_tb_exec`` walks the
fragment list of the previously-executed QEMU TB up to the last-
executed fragment (identified by the scoreboard's ``prev_start_pc``
slot, which each fragment's first raw instruction writes via an
inline store) and feeds those fragments to the chain.  When the
chain forms a complete true BB the assembler seals it via
``commit_true_bb`` into ``bb_map_`` (the *true-BB* cache, keyed by
the branch-target PC of the BB's entry).  This is the cache whose
contents are renumbered into template IDs and serialized to the trace.

On a delay-slot ISA a branch and its delay slot can land in
*separate* TBs — QEMU never lets a TB cross a page boundary, so a
branch sitting on a page's last instruction is split from the delay
slot that follows it.  The assembler folds both TBs into the one
true BB: a ``BARE_BRANCH`` fragment leaves the chain pending until
the next TB (carrying the delay slot) completes it.  Reasoning about
true-BB boundaries per-TB — "this TB ends in a branch, therefore
seal" — is unsound for exactly this reason; ``TbTerminus`` plus the
assembler's pending-delay-slot state is the sound replacement.

The user-visible difference: ``tb_count`` is the number of fragments
the splitter produced across all QEMU translations, while
``bb_count`` (the ``BB templates created`` line in the exit-time
summary) is the number of architectural basic blocks the trace
describes.  Per-segment resets clear ``bb_map_`` only;
``tb_templates_`` survives across segment boundaries because each
QEMU TB carries its fragment list via the per-TB exec-cb ``udata``
for the QEMU TB's lifetime.  ``tb_templates_`` is dropped wholesale
by the ``vcpu_tb_flush`` callback, when QEMU has just invalidated
all of its own TBs (and therefore the udata pointing at our list
entries).

Subsystem map
-------------

The plugin is split into single-responsibility translation units, each
with a header that owns its public surface.  Listed roughly in the
order they're touched on a hot path:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Translation unit
     - Responsibility
   * - ``champsim_tracer.cc``
     - Plugin entry point.  Owns ``qemu_plugin_install``, the
       ``vcpu_tb_trans`` / ``vcpu_tb_exec`` / ``vcpu_tb_flush``
       callbacks, segment lifecycle, and the exit-time statistics
       printer.
   * - ``champsim_tracer_plugin_config.{h,cc}``
     - Parses ``key=value`` plugin args into a ``PluginConfig`` POD.
       New flags get an entry in the setter table here.
   * - ``champsim_tracer_decode.cc``
     - Maps Capstone's per-ISA mnemonics to ``GenericOpcode`` /
       ``BranchType`` / ``GenericRegId``.  This is the only place that
       knows how a particular ISA spells "add."
   * - ``champsim_tracer_mnemonics.h``
     - Declares the classification table types
       (``InsnClassification``, ``RegClassification``) and the shared
       per-ISA architectural-property surface (delay slots, etc.).
   * - ``champsim_tracer_mnemonics_<isa>.h``
       (``x86`` / ``aarch64`` / ``mips`` / ``riscv``)
     - The per-ISA classification tables themselves: ``<isa>_insn_class[]``
       (generic opcode, branch type, atomic flag, dependency refiner)
       and ``<isa>_reg_class[]`` (Capstone register ID to
       ``GenericRegId`` plus GDB-stub feature/name).  Auto-generated by
       ``champsim_tracer_mnemonic_audit.py``.
   * - ``champsim_tracer_mnemonic_tables.cc``
     - The shared dependency-refiner functions (``dep_all_to_all`` and
       the per-behaviour-group refiners) the classification tables'
       ``.dep_refine`` slots point at.
   * - ``champsim_tracer_scoreboard.{h,cc}``
     - The per-vCPU scoreboard.  Inline stores registered on each
       *fragment's* first raw instruction publish that fragment's
       start PC, fall-through PC, and ``TbTerminus`` here for the
       next ``vcpu_tb_exec`` to read.  The last fragment to actually
       execute is the one whose stores fired last, so the scoreboard
       always describes the executed tail — even when a mid-TB
       branch diverted control past later fragments in the same TB.
   * - ``champsim_tracer_generic_ids.h``
     - The portable enum domains: ``GenericOpcode``, ``BranchType``,
       ``GenericRegId``.  Everything in the plugin and the decoder
       agrees on these IDs.
   * - ``champsim_tracer_bb_template_cache.{h,cc}``
     - Owns ``tb_templates_`` (a vector of per-fragment templates,
       one entry per fragment produced by the splitter; cleared
       wholesale on ``vcpu_tb_flush``) and ``bb_map_`` (an
       ``unordered_map`` keyed by branch-target start_pc holding the
       *true* basic-block templates assembled from contiguous
       fragments).  Per :doc:`reference`, ``bb_map_`` is the
       templates section of the trace.
   * - ``champsim_tracer_bb_chain_assembler.{h,cc}``
     - Walks a chain of TB fragments and finalizes them into a true BB
       at the next branch.  See :ref:`cp-flow`.
   * - ``champsim_tracer_branch_history.{h,cc}``
     - Per-branch indirect-target history used to pick the wrong-path
       target on indirect / conditional branches.
   * - ``champsim_tracer_mem_access_recorder.{h,cc}``
     - The ``vcpu_mem_cb`` sink.  Buffers per-thread CP memops in a
       TLS vector and per-WP-simulation memops in
       ``g_wp_state.mem_accesses``.
   * - ``champsim_tracer_reg_snap_collector.{h,cc}``
     - Captures destination-register values per instruction (templates
       enumerate the live dst keys; sources are not snapshotted).  CP
       and WP both use the same per-insn callback to read each insn's
       dst values when its successor canonical insn pre-execs in the
       same TB / fragment; only the trailing insn of each WP fragment
       falls back to a live post-fragment read.  See
       :ref:`regdata-semantics` for the per-path timing detail.
   * - ``champsim_tracer_wp.cc``
     - The wrong-path simulator.  Saves CPU state, enters spec mode at
       a wrong target, runs ``cpu_plugin_exec_tb`` until depth budget
       or natural branch end, restores state.  See :ref:`wp-flow`.
   * - ``champsim_tracer_output.cc``
     - Wire-format encoder.  Owns the BitWriter, the unified
       field-delta state tables, and the templates / trailer writers.
   * - ``champsim_tracer_writer.{h,cc}``
     - Bounded SPSC queue + writer thread.  Decouples the per-segment
       producer from disk I/O.
   * - ``champsim_tracer_trace_segment_manager.{h,cc}``
     - Owns the active segment's lifecycle: window bounds, body stream,
       async writer, atomic shutdown flag.
   * - ``champsim_tracer_simpoint_manager.{h,cc}``
     - Parses a SimPoint file and feeds the segment manager one window
       at a time.
   * - ``champsim_tracer_stats.h`` / ``champsim_tracer_stats.cc``
     - Plain POD aggregate of plugin-wide counters; one global
       ``g_stats`` and (when ``histogram=N``) per-interval buckets.

A handful of synchronization primitives sit at the top of
``champsim_tracer.cc``: ``data_lock`` guards the BB caches and chain
assembler; ``exec_lock`` serializes the per-vCPU execution callback so
the WP simulator can run synchronously inside it.

.. _cp-flow:

Correct-path flow
-----------------

Per TB executed on the correct path, ``vcpu_tb_exec`` runs:

1.  Bump ``insn_count`` by ``n_insns`` of the TB's head fragment.
2.  Window check.  If we're outside an open segment but the icount has
    crossed the next configured window, open a new segment via
    ``start_trace_segment``.  If we're past the segment's stop, close
    it and (for SimPoint mode) advance to the next window.
3.  Read the previous TB's last-executed fragment's start PC, fall-
    through PC, and the current PC from the per-vCPU scoreboard.
    Those fields are populated by inline stores
    ``vcpu_tb_trans`` registered on the *first raw instruction of
    each fragment*, encoding that fragment's parameters.  A
    fragment that never executes (e.g. its predecessor's mid-TB
    branch took, diverting control past this fragment) never fires
    its store; the last fragment to actually execute therefore
    leaves its own values in the scoreboard, which is exactly what
    the chain assembler needs to fold.
4.  Walk the previously-executed QEMU TB's fragment list from the
    head fragment (stashed in ``g_cp_prev_tb_template`` by the
    *prior* ``vcpu_tb_exec``) up to the fragment whose ``start_pc``
    matches the scoreboard's ``prev_start_pc``.  For each fragment
    in the walk: append it to the in-flight CP chain (passing its
    ``TbTerminus``), bump per-instruction attribution
    (opcode / branch-type / src-reg / dst-reg counters in
    ``g_stats``, mirrored into the active histogram bucket), and if
    the chain assembler reports ``bb_complete()`` queue a finalize.
    The assembler is ``reset()`` between finalizes so consecutive
    fragments in the same walk don't get appended onto a just-
    committed chain.
5.  For every queued finalize, derive the branch decision from the
    finalized true BB's terminating branch — never a single fragment.
    Update the :class:`BranchHistory` record (so the WP simulator
    has indirect targets to mine later) and resolve the wrong-path
    target (the fall-through for a taken direct branch, the
    translator-resolved static target for a not-taken direct
    branch, the most-frequent-non-CP indirect target for an
    indirect branch).
6.  Release ``data_lock``, then call ``emit_finalized_bb`` on each
    queued finalize: it optionally invokes the WP simulator for the
    resolved wrong target, builds a :class:`BodyEntry` from the
    just-finalized BB plus the drained per-thread memop / reg-snap
    accumulators, and streams it through the writer.

Steps 4-5 happen under ``data_lock``; the BB cache writes plus chain
state and the WP-target resolution are mutated there.  ``data_lock``
is released before step 6 — the WP simulator and the body-stream
write run under ``exec_lock`` only.  The writer is internally
synchronized.

.. _wp-flow:

Wrong-path flow
---------------

The WP simulator is a synchronous nested loop kicked off from
``emit_finalized_bb``.  It runs entirely under the caller's
``exec_lock`` (``data_lock`` is dropped/reacquired around each cache
operation):

1.  ``qemu_plugin_cpu_state_save`` snapshots the vCPU state we'll roll
    back to.  ``qemu_plugin_spec_mode_begin`` flips QEMU into a
    side-effect-suppressed execution mode and ``qemu_plugin_set_pc``
    redirects to the wrong target.  The plugin's per-vCPU scoreboard
    is also stashed (it'll be restored verbatim before we return so CP
    flow doesn't see the speculative writes).
2.  Loop until the depth budget is exhausted *and* the in-flight BB is
    empty:

    a.  Early-out if ``pre_pc`` is in ``g_poisoned_pcs`` (see
        :ref:`poison-detection`): the speculator has tried to enter
        this PC before and the translation-time detector flagged it
        as non-stable bytes.  Drop the in-flight accumulator and end
        the WP chain.
    b.  Look up the cached *true-BB* at ``pre_pc``.  If absent, the
        fragment template the next ``exec_tb`` produces becomes the
        driver via ``g_wp_state.last_executed_tb``.
    c.  Clear the per-thread WP regsnap scratch buffer
        (``wp_pending_reg_snaps``) if WP reg-data is enabled.  The
        in-flight ``exec_tb`` below will fire the per-insn
        ``vcpu_insn_reg_snap_cb`` registered at translation time, and
        in WP context those callbacks append into this buffer
        instead of the CP-side ``pending_reg_snaps``.  See
        :ref:`regdata-semantics` for the per-path timing.
    d.  ``cpu_plugin_exec_tb()`` runs the TB.  Memory, instruction-
        exec, inline-store, and ``vcpu_tb_exec`` callbacks all fire —
        ``CF_MEMI_ONLY`` was removed so that the plugin's per-fragment
        ``vcpu_tb_exec`` can stash the just-executed template into
        ``g_wp_state.last_executed_tb`` via the same per-TB-udata path
        the CP walker uses.  The plugin distinguishes WP-mode
        invocations from CP-mode via the thread-local
        ``g_wp_state.in_progress`` flag and short-circuits CP-only
        state mutations on the WP path.
    e.  Walk the fragment list of the just-executed QEMU TB.  For
        each fragment determine ``n_executed_in_cur`` via ``post_pc``
        matching against the fragment's own ``insn_pcs`` (on success)
        or fault-PC matching (on a fault).  Append the executed
        prefix's insns to ``bb_pcs`` / ``bb_fields`` / ``bb_bytes`` /
        ``bb_sizes``, bump per-WP attribution counters, and attribute
        the just-captured memops to insn indexes.
    f.  After each fragment, check ``bb_complete``: a ``COMPLETE``
        terminus or a delay-slot landing for a previously-pending
        ``BARE_BRANCH`` seals the in-flight WP BB.  Commit the
        accumulator to the BB cache via ``commit_true_bb_refs``,
        push a :class:`WPBBEntry`, ``clear_accum``, and start the
        next BB with the next fragment's ``start_pc``.  A single
        ``exec_tb`` can therefore commit multiple BBs (one per
        mid-TB branch the splitter found).
    g.  If a fragment faulted on a non-branch insn, mark
        ``bb_has_fault`` / ``bb_first_fault_idx`` (first fault wins),
        poison the faulting PC against re-faults, set the next PC
        to ``fault_pc + last_insn_size``, and continue the outer
        iteration.  Faults on a ``BARE_BRANCH`` fragment do *not*
        force-commit (the delay slot is in a different TB and
        never landed) — they take the skip-past-and-retry branch.

3.  ``qemu_plugin_spec_mode_end`` + ``qemu_plugin_cpu_state_restore``
    +  scoreboard restore.

The chain returned to the caller is *moved* into the
:class:`BodyEntry`'s ``wp_entries`` field and serialized inline within
the same body record as its CP entry.

.. _caveats:

Caveats
-------

These are deliberate design decisions whose rationale is not
apparent from the source alone:

*BBs always end in a branch.*  Per :doc:`/format`, ``bb_map_`` only
holds true basic blocks: the run from a branch target up to the next
branch.  The WP simulator traces *past* in-flight faults precisely
to preserve this invariant — see step 2g above.  True-BB shapes are
*deterministic* by construction: at a given ``start_pc`` the
sequence of instructions up to the terminating branch is a function
of static binary content alone.  Any commit attempt whose shape
disagrees with the cached BB indicates either real self-modifying
code or that the trace is reading dynamic memory as if it were code
— the poison detector below catches the second case at translation
time, before a divergent fragment can ever reach commit.

.. _poison-detection:

Translation-time poison detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before materializing a fragment, ``vcpu_tb_trans`` runs two
stability checks on every canonical insn in the candidate TB:

* **Capstone decode failure** — an empty mnemonic means the bytes
  do not parse as a valid instruction for the target ISA.  Real
  code does not fail to decode.
* **Byte change since first sighting** — every per-PC 4-byte
  instruction word is memoized in ``g_first_insn_word`` on first
  observation.  A subsequent translation of the same PC whose bytes
  differ from the memoized value means the underlying memory is
  writable storage being interpreted as code (stack / heap / .bss
  / .rodata frame the program is writing through).  Real code does
  not change.

Either signal poisons the TB's ``start_pc`` (adding it to
``g_poisoned_pcs``); the fragment is *not* created and no exec-cb
``udata`` is registered for the TB.  Subsequent WP walks check
``cst_pc_is_poisoned`` at the top of each iteration and abort
before re-translating the address.  When poisoning fires inside the
main binary's text segment (``[qemu_plugin_start_code(),
qemu_plugin_end_code())``) the plugin emits a one-shot SMC-suspect
warning to stderr — that is the actual self-modifying-code signal.
Out-of-text-segment poison fires silently because the symptom is
"WP wrong-pathed into data," which is normal speculative behaviour
the tracer just refuses to record.  Both the byte-memo and the
poison set are dropped on ``vcpu_tb_flush``.

*REP-prefixed x86 string instructions fan out per iteration.*  An x86
``REP MOVS`` executes N times against architectural memory.  The
tracer surfaces each iteration as its own ``BODY_TAG_ENTRY``: iter 1
stays on the BB that *enters* the REP loop (terminating that BB at
the REP's PC), and iters 2..N each emit a fresh body entry on a
1-insn self-loop BB whose start_pc == fall_through_pc == the REP's
own PC.  See the *"REP-prefixed self-loop BBs (x86)"* subsection of
*Part II §5.2 "Memory Counts and Addresses"* of the wire-format spec
for the encoding details.
The REP-self-loop BB's terminating insn carries
``branch_type = BRANCH_REP`` to alert consumers that the BB is a
synthetic 1-insn self-loop rather than an ordinary direct conditional
branch.

CP-side capture is straightforward: each iteration's memops attach to
that iteration's own body entry (1 load + 1 store on REP MOVS, 1 store
on REP STOS, etc.), so the slotted families ``CST_FID_LOAD_ADDR*`` /
``CST_FID_STORE_ADDR*`` stay well within their 0..63 range even on
long REP runs.  ``MemAccessRecorder::record`` caps per-instruction
memops at ``CST_FID_SLOT_COUNT`` = 64 and drops the rest — there is
no overflow vector — which also bounds the WP simulator's spec mode,
where ``REP`` can iterate arbitrarily many times against a sandboxed
memory.  The matching
forward-progress guard inside the WP loop catches the related case
where spec-mode ``REP`` returns from ``exec_tb`` without advancing
PC and would otherwise spin forever.

*atexit ordering inversion.*  QEMU registers its plugin atexit
callback *before* the plugin shared object's own ``__cxa_atexit``
destructors run.  By the time ``plugin_exit`` fires, the C++
containers in ``g_bb_template_cache`` and ``g_branch_history`` have
already been destroyed and their ``size()`` returns 0.  The plugin
therefore mirrors the relevant cardinality counts as raw ``uint64_t``
in ``g_stats`` (``tb_templates_created`` etc.) and bumps them at
insertion time, so the exit-time summary still reports useful numbers.

*Thread-locals at exit.*  The CP memop accumulator is a TLS vector.
On REP-heavy workloads it can be MiB-sized and backed by a direct
``mmap``.  Forcing ``shrink_to_fit`` from atexit SIGSEGVs deep in
``__libc_free`` because some glibc heap state is already torn down by
that point.  ``cleanup_current_thread`` therefore only ``clear()`` s;
the TLS destructor runs the natural vector destructor afterwards.

*GMutex, not std::mutex.*  ``<mutex>``'s transitive include chain
pulls ``<cctype>``, which goes through QEMU's ``include/qemu/ctype.h``
shadow that breaks libstdc++'s ``using ::isalnum;`` declarations.  The
plugin uses ``GMutex`` everywhere to avoid that build-time hazard.

*TB-flush longjmp hazard.*  During WP execution
``tb_gen_code()`` may call ``tb_flush()`` on a full code buffer,
which ``longjmp`` s past ``simulate_wrong_path_ext``'s cleanup.
The ``vcpu_tb_flush`` callback must reset the ``g_wp_state``
fields itself or ``vcpu_tb_exec`` stays permanently suppressed
(``in_progress`` never clears); it also drops the partial CP chain,
since splicing pre- and post-flush fragments would fabricate a BB.

*Segment-generation stale-fragment guard.*  Switching segments
calls ``clear_bb_map()``, which drops the owning ``unique_ptr`` s
so any ``BBTemplate*`` held in another thread's in-flight chain
dangles.  ``reset_segment_local_state`` bumps a monotonic
``g_segment_generation``; every chain stamps the generation on each
``append_fragment`` and self-resets on mismatch, so one thread can
reset segment-local state without reaching into other threads'
``thread_local`` chains.  ``vcpu_tb_exec`` independently
re-validates ``prev_tb_tmpl`` via ``find_tb_template``.

*The async writer exists to protect guest timing.*  Without it the
~64 KiB kernel pipe buffer is the only slack between the QEMU CPU
thread and a ``popen``'d compressor (``xz -T0`` etc.); every
compressor stall would block the CPU thread and deform the guest
workload's timing.  It is an SPSC chunked queue (~64 MiB in
flight), one per ``TraceSegment``.

*cap_mode is resolved lazily.*  The Capstone architecture is fixed
at install from ``target_name``, but the mode may introspect the
guest binary via ``qemu_plugin_path_to_binary()``, which needs a
live vCPU context — so it is resolved on the first
``vcpu_init_cb``, not at install.

*Register IDs are 8-bit.*  ``GenericRegId`` reserves the full
0..254 range and 255 is the count sentinel.  An ISA that needs more
than 256 distinct architectural registers requires a wire-format
change — not just an added enum value.

*WP overlay persists across chains.*  Hot speculatively-touched
templates pay first-observation cost only once per trace.  Lookups
hit the WP overlay first, fall back to the CP overlay, then to the
template default.  Updates always go to the active overlay (CP for
CP records, WP for WP records); the WP overlay never modifies CP
state, so CP reconstruction is unaffected by speculative side
effects.

*IFRAMEs are validation-only redundancy.*  When the writer is run
with ``iframe_rate=N``, every Nth observation of a CP template is
followed by a ``BODY_TAG_IFRAME`` body record that re-encodes the
same body record (CP + WP chain + WP events) against fresh scratch
overlays — every value lands as an absolute delta-from-template-
default.  IFRAMEs MUST NOT advance ``prev_entry_template`` or update
``cp_field_state`` / ``wp_field_state``; they exist solely so a
decoder can cross-check that its delta-replay produced the same view
the writer had.  Flagging the CP triggers an IFRAME; the IFRAME then
covers every WP entry attached to that CP.  WP entries are never
IFRAME'd independently.

*Prefetch / cache / TLB EAs are synthesized.*  Software prefetches
(x86 ``prefetch*``, AArch64 ``prfm``, RISC-V ``prefetch.*``,
MIPS ``pref``), addressed cache-line ops (``clflush*``, ``clwb``,
``cldemote``, ``dc.*``, ``ic.*``, ``cbo.*``, ``cache``), and
addressed TLB invalidations (``invlpg*``, ``tlbi``, ``sfence.vma``,
``hfence.*``, MIPS ``tlb*``) translate to TCG no-ops in QEMU, so the
plugin's mem-callback never fires for them.  ``decode_synthetic_ea``
captures the operand at translation time, and a per-insn exec
callback reads the base / index registers at exec time to compute
``ea = base + (index << shift_amount) * scale + disp``.  The result
is funneled through ``MemAccessRecorder::record_synthetic_load`` so
it shows up in the ``LOAD_ADDR[0]`` slot the same way a normal load
would.  This relies on the ``scale`` (x86 SIB) and
``shift_type`` / ``shift_amount`` (AArch64) fields the plugin's
QEMU base adds to ``qemu_plugin_operand`` — see :doc:`extending`.
The WP path runs the same ``vcpu_mem_cb`` plumbing as the CP path
(``CF_MEMI_ONLY`` is no longer set on the speculative TBs), so
mem-callback-driven capture stays correct under speculation.

*Sibling TB translations get distinct fragment lists.*  When QEMU
translates the same start_pc more than once (different cflags —
notably the wrong-path simulator's ``CF_NO_GOTO_TB`` /
``CF_SINGLE_STEP`` translations — or a page flush + retranslate),
each translation produces its own splitter output and its own
fragment list.  ``tb_templates_`` is a vector, not a start_pc-keyed
map, so sibling translations never overwrite each other: the per-TB
exec-cb ``udata`` always points at the exact list the just-executed
QEMU TB produced.  For real binary code the canonical-insn arrays
are identical across siblings (the static bytes don't change), so
the splitter produces the same fragment shape every time and the
chain assembler folds it deterministically.  When the bytes *do*
appear to change — the dynamic-memory speculation case — the
poison detector (see :ref:`poison-detection`) catches it at
translation time and refuses to materialize the fragment at all.

*Stats are exact, lock-free on the bump path.*  ``g_stats`` is a macro
that forwards to a per-thread heap-allocated ``Stats`` slot via
``thread_stats_get()``.  Bumps touch only thread-local memory, no
atomics, no locks.  ``stats_snapshot()`` produces a coherent
process-wide aggregate by walking a registry of every thread's slot
under ``stats_registry_lock`` (acquired exactly once per thread at
first touch, again at thread exit, and from each read site —
segment-summary points and ``plugin_exit``).  Threads that exit before
``plugin_exit`` fold their slot into a graveyard accumulator on TLS
destruction so their contributions still appear in the final total.

Histogram bucket increments are not atomic and don't need to be:
``g_current_hist_bucket`` is mutated and read only under
``exec_lock``, which the CP and WP attribution paths both hold.

Histogram buckets
-----------------

When ``histogram=N`` is set, ``start_trace_segment`` allocates N
``Stats`` zero-init buckets and computes ``interval_size = ceil(span /
N)``.  At the top of each ``vcpu_tb_exec`` we set
``g_current_hist_bucket`` to the bucket whose interval contains the
current icount.  Both the CP attribution loop in ``vcpu_tb_exec`` and
the WP attribution loop in ``simulate_wrong_path_ext`` mirror their
``g_stats`` bumps into ``*g_current_hist_bucket`` when non-null.

The WP path runs synchronously while ``exec_lock`` is still held by the
outer ``vcpu_tb_exec``, so the bucket pointer set at the top of CP
attribution is still valid and current when WP appends — no extra
plumbing needed.

At ``finish_trace_segment`` the buckets are dumped via
``append_histogram``: a headline table with one row per interval, then
transposed top-K tables for opcode / branch type / src reg / dst reg
where columns are intervals.

Synchronization summary
-----------------------

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Lock
     - Covers
   * - ``exec_lock``
     - Held during ``vcpu_tb_exec`` so CP attribution, chain
       assembly, and a synchronous WP simulation all serialize.  Also
       held during ``vcpu_tb_flush`` reset and ``plugin_exit``.
   * - ``data_lock``
     - Mutates the BB caches (``tb_templates_``, ``bb_map_``), the
       byte-stability / poison maps (``g_first_insn_word``,
       ``g_poisoned_pcs``), the chain assembler's fragment list, and
       ``g_branch_history``.  Acquired briefly inside the larger
       ``exec_lock`` window.
   * - ``unknown_warn_lock``
     - Serializes writes to the ``.unknown_warnings.log`` sidecar.
   * - Plugin writer thread
     - Internally synchronized SPSC queue.  Producers (segments) push
       fully-formed binary buffers; the writer thread drains them to
       disk.

The two-lock layout: ``exec_lock`` serializes the per-vCPU execution
callback (one ``vcpu_tb_exec`` at a time, including any synchronous
WP simulation it triggers — so WP runs without needing to stack
saved state across nested invocations).  ``data_lock`` is grabbed
briefly inside that long window only when mutating cache state, so
the WP simulator can drop and reacquire it across each cache write
without holding the whole simulation under one lock.
