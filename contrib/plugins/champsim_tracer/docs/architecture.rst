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
   single: PathBuilder
   single: path-event queue
   single: TemplateStore
   single: TmplLife
   single: SegRef
   single: marker window
   single: ASID pin
   single: fault excursion
   single: async-interrupt exclusion
   single: vclock

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
  so consumers can reconstruct per-thread sub-streams by filtering.
* **``thread_id`` names a guest thread, not the vCPU.**  The vCPU
  (host scheduling slot) is deliberately absent from the wire — the
  consumer owns the thread-to-core mapping, not the tracer.  In a
  user-mode trace each guest thread is its own host thread and
  ``thread_id`` is that thread's index.  In a **system-mode pinned**
  trace the id is resolved from the guest kernel's per-thread pointer
  register (x86 ``FS.base``, AArch64 ``TPIDR_EL0``, RISC-V ``tp``,
  MIPS CP0 ``UserLocal`` — :c:func:`qemu_plugin_get_thread_ptr`),
  sampled at user privilege for the pinned process and mapped to a
  compact id in first-sighting order within the segment.  Because that
  pointer follows the software thread, the id is **stable across vCPU
  migration**: a thread the guest scheduler moves between vCPUs keeps
  one ``thread_id``, and two threads time-slicing a single vCPU are two
  distinct ids — the opposite of a vCPU index, which would split the
  first and merge the second.  A single-threaded pinned process is
  ``thread_id`` 0 regardless of which vCPU(s) it ran on; kernel entries
  inherit the tid of the thread that entered the kernel (a kernel TB
  before any user TB of the segment reads as thread 0).  Each segment's
  body opens with an explicit ``BODY_TAG_THREAD_SWITCH`` naming the
  starting thread; the per-segment thread-id map is reset at each open.
  *Degradation:* a target/model whose thread-pointer register is never
  written (no MIPS ``Config3.ULRI``, a guest that sets no TLS) reports
  0 for every thread, so its threads collapse to one id — honest
  indistinctness, never a fabricated identity.  For the attribution
  envelope and the migration boundary see :ref:`single-address-space`.
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
  records are emitted only when the running guest thread differs from the
  previous body record's.  Single-threaded workloads pay
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

.. _single-address-space:

Single address space (system-mode scope)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A system-mode trace represents **one address space**.  The marker pins a
single process, every virtual address in the body is that process's, and
``thread_id`` distinguishes the software threads *within* it — nothing in
the wire disambiguates memory across processes (the same VA in a different
address space is different memory).  Whole-system / multi-process tracing
would require an address-space id (CR3 / TTBR0 / SATP / MIPS ASID) on the
wire so a consumer could key memory per process; that is a deliberate
**future** format extension, not a current capability.

Within that one address space, clean per-thread attribution rests on the
pinned process **not migrating across vCPUs**:

* **User code is exact.**  ``thread_id`` is read from the per-thread
  pointer, a user register the kernel context-switches, so a thread's
  user-space blocks carry one id wherever the guest scheduler runs them —
  stable across a migration.
* **Kernel code is attributed by entry, within a vCPU.**  A user-to-kernel
  excursion (syscall, fault handler) inherits the tid of the thread that
  entered it on that vCPU.  This is correct while the process stays on one
  vCPU.  It has **no architecturally-clean answer across a migration**:
  kernel code carries no per-thread register (the thread pointer is a user
  register; no ISA exposes a kernel-privilege one), so scheduler /
  context-switch code the guest runs on a vCPU a thread has just left, or
  arrives on before reaching user, belongs to no single thread the wire
  can name.

The tracer therefore treats a migrating pinned process as **outside the
clean-attribution envelope** rather than fabricating a kernel-thread
identity for it.  The supported path keeps it inside the envelope by
pinning: :program:`cst_attach` confines the target to one guest CPU by
default (``--pin-cpu N`` / ``--no-pin``), and ``taskset`` / ``isolcpus``
do the same for a compiled-in marker.  When a segment nonetheless observes
the pinned process running **user** code on more than one vCPU — the
architectural migration signal — the plugin emits **one** stderr warning
per segment and sets the ``pin_multivcpu_observed`` stat, making the
misuse loud rather than silent.  Only the user-code tid is guaranteed
across such a migration; the per-vCPU kernel-nesting discipline the
validator's ``syscall_fault_nesting`` check asserts is relaxed at the
migration seam for exactly this reason (a documented boundary, verified by
the forced-migration test, not a papered-over defect).

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
for the QEMU TB's lifetime.  Fragment templates carry a lifetime
class: templates the correct path executes (``CODE``) persist for the
whole run — a QEMU ``tb_flush`` merely re-translates the same code,
and the dedup index hands the re-translation its existing chain —
while templates only wrong-path speculation ever minted (``SPEC``)
are reclaimed at the flush.  See :ref:`template-lifetimes` for the
full lifetime model.

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
       callbacks, segment lifecycle, the marker / address-space-pin
       machinery, and the exit-time statistics printer.
   * - ``champsim_tracer_path_builder.{h,cc}``
     - The per-vCPU-thread CP step state machine.  Consumes the
       ordered per-vCPU path-event queue and owns everything
       path-shaped: the async-exclusion mute window, the foreign-ASID
       boundary, the pending-seal slot (the deferred previous TB),
       the fault-excursion context frames, and the seal / merge /
       emit decision.  See :ref:`path-builder`.
   * - ``champsim_tracer_wp_thread_state.{h,cc}``
     - Per-thread wrong-path session state (``g_wp_state``: the
       in-progress flag, the ``last_executed_tb`` handshake, saved
       scoreboard cursors, the WP memop buffer) and the per-thread
       capture-mute latch ``g_capture_mute``.
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
     - The ``TemplateStore`` (the file keeps its historical name so
       build entries stay stable).  Owns ``tb_templates_`` (the
       per-translation fragment templates, one entry per fragment
       produced by the splitter, with ``SPEC`` / ``CODE`` lifetime
       classes and per-class dedup indexes) and ``bb_map_`` (an
       ``unordered_map`` keyed by branch-target start_pc holding the
       *true* basic-block templates assembled from contiguous
       fragments; segment-scoped).  ``bb_map_`` is the templates
       section of the trace.  See :ref:`template-lifetimes`.
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
``champsim_tracer.cc``: ``data_lock`` (a ``GMutex``) guards the
template stores and chain assembler; ``exec_lock`` (a ``GRecMutex``)
serializes the per-vCPU execution callback so the WP simulator can
run synchronously inside it.  See `Synchronization summary`_ for why
``exec_lock`` is recursive.

.. _cp-flow:

Correct-path flow
-----------------

``vcpu_tb_exec`` fires once per executed TB.  It is registered as a
conditional callback on the scoreboard's ``trace_this_ctx`` slot,
which folds ``is_active`` together with pinned-context ownership: the
JIT skips the dispatch entirely between segments *and* for any TB the
trace does not own.  Its ``udata`` is the head fragment of the TB's
per-translation fragment list.  The callback has two layers: a short
shared prologue, then the PathBuilder step.

``trace_this_ctx`` is a bare ``is_active`` mirror everywhere the
ownership question is trivial — user mode, an unpinned system trace,
and the wide-register system pins (CR3 / TTBR0 / SATP) whose ASID is
a reliable per-process id, foreign-dropped inside the step as before.
It diverges only for a **narrow-ASID (MIPS) system pin**, where a
recycled ``EntryHi.ASID`` cannot distinguish processes: there only a
physical-page-confirmed dwell traces, and a separate light callback,
``vcpu_pin_probe`` (gated on the companion ``pin_probe`` slot,
registered ahead of ``vcpu_tb_exec``), runs for every other in-segment
TB.  The light probe carries the whole per-foreign-TB budget — a
user-clock cursor tick, the physical-page content probe on user TBs,
and the capture mute the heavy drop path used to set — with no
``VClockPauseGuard`` and no PathBuilder step; on the TB that
re-acquires the pinned process it flips ``trace_this_ctx`` to 1 so the
heavy callback's re-loaded brcond fires for that same TB.  Both slots
are maintained event-driven (``refresh_ctx_gates``): at every
``is_active`` edge, at each committed ASID write, and on a re-acquiring
probe — never on the per-TB path.  This is what keeps a churning
guest, where a rollover hands the pinned ASID value to a stream of
foreign processes, from paying the guest-clock freeze on millions of
dropped foreign TBs (the throttle that otherwise collapses the guest
virtual clock to a fraction of realtime).

**Shared prologue** (before any lock):

1.  **WP early-out.**  When ``g_wp_state.in_progress`` is set, this
    invocation is the wrong-path simulator's nested ``exec_tb`` on
    the same thread: stash the template in
    ``g_wp_state.last_executed_tb`` and return.  The CP frame that
    kicked the simulation already holds ``exec_lock``; the WP branch
    touches only thread-local state and never runs the CP machinery.
2.  **Promote.**  Correct-path execution promotes the TB's whole
    fragment chain to the ``CODE`` lifetime class
    (``TemplateStore::promote``), protecting chains the wrong path
    minted first from the SPEC reclaim.  A racy pre-lock read of
    ``chain_indexed`` keeps the steady state lock-free; ``promote()``
    rechecks under ``data_lock``.  See :ref:`template-lifetimes`.
3.  **Capture-mute latch.**  ``g_capture_mute`` latches
    ``qemu_plugin_in_async_int()`` for this TB before any early
    return: the per-memop, reg-snap, and synthetic-EA callbacks all
    consult the latch, so even a TB the step later suppresses has
    its captures dropped.  See :ref:`async-exclusion`.
4.  **Guest-clock guard.**  A ``VClockPauseGuard`` freezes the guest
    virtual clock for the rest of the callback — everything below is
    instrumentation cost, not guest execution.  See
    :ref:`time-transparency`.
5.  **icount read.**  The per-TB ``INLINE_ADD_U64`` is emitted ahead
    of this callback, so the scoreboard's ``insn_count`` already
    includes this TB; the value read here drives window management.

**The step glue** (``events_path_step``) enables the vCPU's
path-event queue lazily on the thread's first CP exec, then runs
everything shared between path outcomes — in an order that is
load-bearing — under ``exec_lock``:

1.  Marker-pin fold: with an address-space pin armed, fold this TB's
    insn-count delta into the user-instruction clock (pinned ASID at
    privilege 0 only) and stamp the fragment's ``is_system`` from
    the live privilege — the correct-path ground truth that a
    wrong-path seed never overrides.  See :ref:`asid-pin`.
2.  Drain the event queue (``qemu_plugin_drain_cpu_events``) into
    the step input and run ``PathBuilder::step_events`` — the
    pre-window phase (async-window arrows, foreign-ASID boundary,
    the pending-seal swap).  Any outcome but ``CONTINUE`` ends the
    step here: an async-suspended TB must not drive window
    decisions.
3.  ``tw_manage_window``: segment open / close / deferred-close
    arming, on the raw icount or (marker mode) the user-instruction
    clock.  A step that *opens* a segment ends at the per-thread
    segment-open boundary: the builder resets
    (``PathBuilder::on_segment_open``), the async state clears, and
    the queue re-enables, discarding the backlog that straddles the
    boundary.
4.  Heartbeat and histogram-bucket selection, then the scoreboard
    reads: ``current_pc`` (the executing TB's start, a per-TB inline
    store) and the previous TB's last-executed fragment's
    ``prev_start_pc`` / ``prev_fall_through``.  The latter two are
    inline stores on each *fragment's first raw instruction*; a
    fragment that never executed (a predecessor's mid-TB branch
    diverted control past it) never fires its store, so the
    scoreboard always describes the executed tail.
5.  ``PathBuilder::step_seal`` — the post-window phase: depth
    stamping, fault-entry classification against the deferred prev,
    the shared seal walk, merge completion, emission.  See
    :ref:`path-builder`.
6.  Only a normally ``SEALED`` step runs the deferred window closes
    (the icount stop, the simpoint advance, and the marker / symbol
    budget close are all deferred to a true-BB boundary so the trace
    covers *at least* the requested window) and consumes the
    spec-flush latch, issuing ``qemu_plugin_request_tb_flush`` once
    no wrong-path excursion is in flight.  The deferral is also what
    keeps the segment's tail well-formed: the budget crossing is
    detected between the pending-seal swap and the seal phase, and a
    close taken at that instant would emit the just-swapped current
    TB twice (once via the segment-final flush, once as a later walk
    of the slot) while dropping the deferred previous TB's entry
    outright.  Deferring to the step tail lets the seal phase emit
    the previous TB normally; the segment-final flush then drains
    the pending-seal slot — the budget-crossing TB whose
    instructions the window clock already counted — exactly once.

**The seal walk** (``collect_finalized_bbs``; shared by the per-step
seal, the fault-merge fold, and the segment-final flush) walks the
deferred previous TB's fragment list up to the last-executed
fragment.  Per fragment: capture the tail instruction's
destination-register snaps (``snap_prev_tail_dsts`` — the one capture
the per-insn hooks cannot reach, since the tail has no successor
hook inside its own TB), append the fragment to the in-flight
true-BB chain with its ``TbTerminus``, bump per-instruction
attribution (opcode / branch-type / src / dst counters, mirrored
into the active histogram bucket), and whenever the chain assembler
reports a complete true BB, finalize it and resolve its terminal
branch: direction from the executed edge, :class:`BranchHistory`
update (the pool the WP simulator mines for indirect targets),
wrong-path-target resolution (the fall-through for a taken direct
branch, the translator-resolved static target for a not-taken one,
the most-frequent-non-CP indirect target for an indirect branch),
and the ``wpprune`` cold-branch filter.  The assembler is reset
between finalizes so consecutive fragments in one walk never append
onto a just-committed chain.  The walk runs under ``data_lock``;
emission (``emit_finalized_bb`` — the synchronous WP kick plus the
body-entry write) runs afterwards under ``exec_lock`` only.  The
writer is internally synchronized.

One deferral is inherent to this shape: TB *N*'s branch outcome and
its tail instruction's post-execution register values are only
knowable at TB *N+1* (the successor's inline ``current_pc`` store
resolves the branch, and between the two TBs the register file still
holds the tail's post-write state).  The PathBuilder's pending-seal
slot is that deferral's single owner — each step seals the
*previous* TB and promotes the current one into the slot — and
``PathBuilder::flush_final`` drains the slot when a segment
finishes, so a TB ended by a process-exiting syscall still emits its
body entry (with no wrong path: speculation past exit is undefined).

.. _path-builder:

Path events and the PathBuilder
-------------------------------

The trace's output is a causally-ordered stream of sealed true BBs;
the input that orders it is the **per-vCPU path-event queue**, a
QEMU-side structure (``CPUState::plugin_evq``, see
:doc:`qemu_modifications`) that delivers path causality as ordered
events rather than sampled state.

**The event-queue contract.**  Four event kinds:

* ``FAULT_ENTER`` / ``FAULT_RETURN`` — a synchronous-fault entry or
  its exception return, appended at QEMU's fault-stack chokepoints
  (``cpu_plugin_fault_push`` / ``cpu_plugin_fault_pop``).  The
  event's ``pc`` is the *resume PC* — the faulting instruction, where
  the handler's exception return lands — and ``depth_after`` is the
  fault-stack depth after the event applies.
* ``ASYNC_ENTER`` / ``ASYNC_RETURN`` — an asynchronous-interrupt
  delivery or the fetch of its departure PC, bracketing the async
  exclusion window (see :ref:`async-exclusion`).  The event's ``pc``
  is the departure PC.

Every event carries the address-space ID and privilege level
**stamped at the event instant**, so a page-fault handler rewriting
the MMU context register mid-excursion cannot drift a frame's
identity.  The queue is single-producer, single-consumer — both are
the owning vCPU thread — so it needs no locking; it grows and never
drops (a dense fault storm delivers one event per entry, none
collapsed); and it is spec-mode-suppressed at the source, so
wrong-path excursions leave it untouched.  It is empty and disabled
until the plugin opts in per vCPU; the plugin enables it lazily at
each thread's first in-segment exec and disables it across
inter-segment gaps (where the exec callback — the only consumer —
does not fire).

The ordering invariant beneath everything below: *an event's effects
belong to the first TB executed after it*.  The events drained at
step *N* happened after the previous TB's execution and before the
current TB's, so they classify the **previous** TB (which executed
before them) and set the depth / mute context the **current** TB
runs under.

**The PathBuilder** (one per vCPU thread, by construction: frames,
chain, capture buffers, and reg-snap accumulators are all
thread-local) consumes the queue and owns all path-shaped state.
Its step is split into two phases around the shared window
management because the gate order is load-bearing on both sides:

``step_events`` (pre-window) retains the step's drained events (the
queue's internal buffer is only valid until the next push; fault
events must survive bailed steps until a seal consumes them), then:

* **Async mute window.**  The ordered ``ASYNC_ENTER`` /
  ``ASYNC_RETURN`` edges drive the mute flag with assignment
  semantics (re-scanning retained events across a bailed step is
  idempotent); until the first per-segment prime the live QEMU flag
  is authoritative.  While excluding, the step suspends: the TB is
  dropped, the pending seal stays untouched, and the resume TB later
  seals the interrupted branch against its real target.  A pinned
  process observed at user privilege inside a supposedly-open window
  is definitionally not handler content, so the window is
  force-closed there (stuck-window recovery — the one local reset
  that produces no event).
* **Foreign-ASID boundary.**  A pinned run executing under another
  address space drops the deferred prev (a one-TB-lossy boundary) so
  its fragments never bridge across the gap.  The async suspend runs
  *first*: an async excursion routinely context-switches through
  foreign address spaces, and those TBs must take the suspend (which
  preserves the deferred prev for the resume), not the drop.
* **The pending-seal swap.**  On ``CONTINUE`` the current TB is
  promoted into the pending-seal slot and the old occupant becomes
  the TB the seal phase walks, together with the fault depth stamped
  when it *executed* (the fault stack may pop between a TB's
  execution and its emission one step later; a seal-time read would
  lose the handler's level).

``step_seal`` (post-window, only on steps that survived the
shutdown / active / segment-boundary gates) applies the retained
fault events exactly once, then runs the shared seal walk:

* **Depth pipeline.**  ``raw_depth_`` tracks the last event's
  ``depth_after``; ``base_depth_`` is the segment baseline, primed
  lazily from live state at the segment's first seal (a fault in
  flight across segment-open is baselined out, and events predating
  the prime are swallowed — entries before a segment's first
  surviving step never stash and never count); the baselined,
  0-clamped difference is the depth the current TB runs at.  When a
  pre-segment fault returns mid-segment and takes raw below the
  baseline, the baseline re-floors to the new raw depth.  The
  re-floor is load-bearing, not cosmetic: the prime also baselines
  in *stale* pre-segment frames — a non-LIFO guest exception return
  (a context switch inside a blocking fault resuming the outer task
  first) never pops its frame, so a busy boot leaves them on the
  per-vCPU stack — and when a later unrelated return matches a stale
  frame's resume PC, the pop is permanent.  A fixed baseline would
  clamp every subsequent excursion's depth to 0 for the rest of the
  segment, mislabelling handler content and breaking the merged-BB
  nesting invariant.  The baseline also re-floors *upward* at a guest
  context switch: an ``ASID_WRITE`` event (the reported address-space
  register genuinely changed) sets ``base_depth_`` to the switch-instant
  depth (its ``depth_after``).  The incoming process is unrelated to
  whatever fault frames the outgoing context left live on the per-vCPU
  stack, so it must measure its own handlers against *its* zero.  The
  archetype the churn battery exercises: a user page fault whose handler
  an asynchronous tick preempts into the scheduler, which switches to
  another task and never returns to pop the frame — a non-LIFO leak that,
  without the up-re-floor, would stamp every subsequent fault under the
  reused ASID one nesting level too deep (the intermittent ``0 -> 2+``
  jump that skips depth 1).  The two re-floors are complementary: the
  ``ASID_WRITE`` case raises the baseline as stale frames accumulate
  across switches, the ``raw < base`` case lowers it when one finally
  pops.
* **Fault-entry classification.**  Each ``FAULT_ENTER`` is handled
  individually against the deferred prev — see
  :ref:`fault-excursions` for the three cases and the context-frame
  (whole-BB merge) machinery.
* **Seal, merge, emit.**  The seal walk collects finalized BBs; if
  the first seal completes a fault frame, the merge emits the frame's
  full template with its accumulated pieces; otherwise every
  finalized BB emits normally.

Segment opens reset the builder (``on_segment_open``): frames are
dropped (their templates point into the just-cleared ``bb_map_``),
the pending-seal slot and retained events clear, the depth pipeline
zeroes and re-primes lazily, and the mute window closes.
``flush_final`` is the segment-finish counterpart: it drains the
pending-seal slot through the same fragment walk (including the
delay-slot tail snaps) so the segment's last TB is not lost to the
one-step deferral.

.. _template-lifetimes:

Template store lifetimes
------------------------

``TemplateStore`` (``champsim_tracer_bb_template_cache.{h,cc}``)
owns every template and expresses lifetime three ways:

* **CODE** — templates for code the correct path executes.
  Persistent for the whole run and *flush-invariant by
  construction*: a QEMU ``tb_flush`` is JIT housekeeping, and a
  re-translation of the same code reuses its existing chain through
  the dedup index (``lookup_tb_chain``, keyed by ``(start_pc,
  canonical insn count)`` — byte identity is guaranteed by the
  poison gate upstream), so a flush frees nothing and perturbs no
  walk state for real code.
* **SPEC** — templates minted by a wrong-path (spec-mode)
  translation (``set_creating_spec`` selects the class at
  translation time).  Wrong-path fetch residue unless the correct
  path later runs it: speculation wandering mutable data that
  happens to decode can mint templates at millions of fresh PCs, so
  retaining them for the run is unbounded heap growth.  They are
  freed wholesale at ``tb_flush`` (``reclaim_spec_templates``) —
  their owning QEMU TBs are gone and, by the deferred-flush
  machinery, no wrong-path walk is in flight when the flush callback
  runs.
* **SEGMENT** — expressed by ``bb_map_`` membership, not by the
  class enum: the true-BB store owns its records and drops them
  wholesale at ``clear_bb_map()`` on every segment switch.

**Class-split dedup indexes.**  The CODE index
(``tb_chain_dedup_``) holds only CODE chains; SPEC-born chains live
in a separate SPEC index populated at creation.  Lookups consult the
CODE index first, then the SPEC index — creation-time SPEC
visibility is load-bearing, because a correct-path translation
routinely *adopts* a chain the wrong path minted first (WP discovers
code before CP reaches it), and a WP translation reuses real code's
chain.  Reclaim is therefore a pure partition: free every still-SPEC
template, clear the SPEC index in one O(1) operation, and never
touch the CODE index.  ``promote()`` is the only SPEC→CODE
transition and the only CODE-index inserter; it converts a *whole*
sibling-fragment chain at once (a mixed-class chain is impossible by
construction) and is idempotent.  A promoted chain's stale SPEC-index
entry is harmless — lookups prefer the CODE index, and the entry
vanishes at the next reclaim.

**The spec-budget latch.**  ``vcpu_tb_trans`` accounts each
SPEC-born template's estimated footprint into
``spec_pending_bytes``; when a wrong-path translation pushes it past
the budget (256 MiB by default — far above any healthy run's
speculative footprint, reached only by a genuine runaway; the
``CST_SPEC_FLUSH_BUDGET`` environment variable overrides it in
bytes, which is also the reclaim live-fire test knob), a flush is
*latched*, not requested: a request mid-excursion would kick the
vCPU and truncate the in-flight chain.  The CP step boundary issues
the actual ``qemu_plugin_request_tb_flush`` once no excursion is in
flight, and the flush callback's reclaim frees everything still
SPEC.

**Cross-lifetime references are generation-stamped handles.**  A
persistent fragment template can point into the segment-scoped
``bb_map_`` (its REP self-loop sub-template ``rep_subtmpl``, its
true-BB back-edge ``parent_true_bb``).  Those are ``SegRef`` handles
carrying the store's segment generation at mint time; staleness is
detected at deref (``seg_deref`` returns null on a generation
mismatch — one integer compare, cheap enough for the REP fan-out hot
path), so ``clear_bb_map()`` needs no invalidation walk over the
persistent translations.  The generation counter is store-owned and
starts at 1, so a zero-initialized handle is stale from birth.

Two environment knobs observe the lifetime machinery:
``CST_MEMSTATS`` prints footprint breakdowns (per-array byte totals,
duplicate-chain histogram, reclaim counts) at segment close and on
creation-rate thresholds; ``CST_LIFE_AUDIT`` enables debug boundary
audits that walk the surviving stores after each lifetime boundary
and abort if any survivor still references reclaimed memory (after
reclaim: no surviving fragment references a freed SPEC template and
survivors are uniformly CODE; after clear: no persistent template
holds a current-generation ``SegRef``).

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

    a.  Early-out if ``pre_pc`` is poisoned (see
        :ref:`poison-detection`): the speculator has tried to enter
        this PC before and the translation-time detector flagged it
        as non-stable bytes.  Drop the in-flight accumulator and end
        the WP chain.  The global poison set is *not* consulted on
        the excursion's very first iteration — the branch predictor
        deliberately chose the wrong target, and a stale entry keyed
        by a start_pc the correct path only ever reaches mid-TB must
        not veto the excursion's entry (the per-TB poison detector in
        ``vcpu_tb_trans`` still refuses a genuinely-garbage first
        TB).  The walk also keeps a per-excursion local poison set
        for PCs that faulted during this excursion.
    b.  Clear the per-thread WP regsnap scratch buffer
        (``wp_pending_reg_snaps``) if WP reg-data is enabled.  The
        in-flight ``exec_tb`` below will fire the per-insn
        ``vcpu_insn_reg_snap_cb`` registered at translation time, and
        in WP context those callbacks append into this buffer
        instead of the CP-side ``pending_reg_snaps``.  See
        :ref:`regdata-semantics` for the per-path timing.
    c.  ``cpu_plugin_exec_tb()`` runs the TB.  The speculative TB
        runs the full callback surface — memory, instruction-exec,
        inline-store, and ``vcpu_tb_exec`` callbacks all fire — so
        the plugin's ``vcpu_tb_exec`` delivers the just-executed
        fragment template into ``g_wp_state.last_executed_tb``
        through the same per-TB-udata path the CP step uses (no
        template-cache lookup on the WP hot loop).  The plugin
        distinguishes WP-mode invocations from CP-mode via the
        thread-local ``g_wp_state.in_progress`` flag and
        short-circuits CP-only state mutations on the WP path.
    d.  Walk the fragment list of the just-executed QEMU TB.  For
        each fragment determine ``n_executed_in_cur`` via ``post_pc``
        matching against the fragment's own ``insn_pcs`` (on success)
        or fault-PC matching (on a fault).  Append the executed
        prefix's insns to ``bb_pcs`` / ``bb_fields`` / ``bb_bytes`` /
        ``bb_sizes``, bump per-WP attribution counters, and attribute
        the just-captured memops to insn indexes.
    e.  After each fragment, check ``bb_complete``: a ``COMPLETE``
        terminus or a delay-slot landing for a previously-pending
        ``BARE_BRANCH`` seals the in-flight WP BB.  Commit the
        accumulator to the BB cache via ``commit_true_bb_refs``,
        push a :class:`WPBBEntry`, ``clear_accum``, and start the
        next BB with the next fragment's ``start_pc``.  A single
        ``exec_tb`` can therefore commit multiple BBs (one per
        mid-TB branch the splitter found).
    f.  A speculative **memory** fault never reaches here: the
        load/store seam serves a deterministic placeholder value and
        returns, so the fragment runs to completion (``tb_ok`` stays
        true).  The memop drain marks ``bb_has_fault`` /
        ``bb_first_fault_idx`` at the placeholder-served instruction
        (first fault wins) and the excursion continues.  A **non-memory**
        synchronous fault (arithmetic / illegal-opcode) still longjmps
        out of spec mode; the walk marks that BB the same way, runs it
        out to its natural branch (avoiding a partial, template-polluting
        commit), and then ends the excursion cleanly at that block —
        the interim graceful stop, pending a value model for the
        faulting result.  Faults on a ``BARE_BRANCH`` fragment do *not*
        force-commit (the delay slot is in a different TB and never
        landed) — they drop the in-flight accumulator and end.

3.  ``qemu_plugin_spec_mode_end`` + ``qemu_plugin_cpu_state_restore``
    +  scoreboard restore.

The chain returned to the caller is *moved* into the
:class:`BodyEntry`'s ``wp_entries`` field and serialized inline within
the same body record as its CP entry.

.. _wp-termination:

Wrong-path chain termination
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every excursion ends in one of a small set of conditions, each with
its own wire semantics.  Consumers should treat them differently:

* **Depth budget.**  ``sim_insns`` reached ``wpdepth`` and the
  in-flight BB has sealed.  The clean, unmarked end: the chain is
  exactly the speculative window a ``wpdepth``-deep frontend would
  fetch, and the consumer simply stops replaying at its end.
* **Synthetic-data fault.**  On a mispredicted path no instruction
  ever retires, so a back-end synchronous fault a speculative
  instruction would raise is never actually taken by a real core — the
  branch-mispredict squash kills the path before commit.  The tracer
  models this instead of truncating.  A speculative **memory** access
  to an absent/unreadable page is served a deterministic pseudo-random
  placeholder value (keyed on the guest address, so the same bad
  address always reads the same bytes and adjacent bytes are
  decorrelated), the sealed :class:`WPBBEntry` is marked ``fault`` plus
  ``fault_insn_index`` at that instruction (``CST_WP_EVENT_FAULT`` on
  the wire), and the excursion **continues** on the placeholder to the
  depth budget.  Everything downstream of the marked instruction is
  synthetic; the **consumer contract** is that the marked instruction's
  result — and anything derived from it — is speculative filler that
  never architecturally retires.  This holds symmetrically in user and
  system mode, and covers loads and atomics; a wrong-path store to an
  absent page is sandboxed rather than faulting, exactly as a
  present-page speculative store is.  A **non-memory** synchronous
  fault (arithmetic / illegal-opcode) still longjmps out of spec mode;
  it is marked the same way but — pending a value model for its result
  — ends the chain cleanly at its marked block (the block runs out to
  its natural branch first, so no partial template is committed).  Such
  a block is the chain's last, distinguished from a memory fault only
  by being terminal.
* **Translation unavailable, mid-chain.**  The *next* wrong-path
  target could not be fetched or translated — un-resident code under
  demand paging is the architectural case.  The last completed
  :class:`WPBBEntry` carries the ``translation_unavailable`` marker
  (``CST_WP_EVENT_TRANSLATION_UNAVAIL`` on the wire), making the
  honest fetch boundary distinguishable from a clean budget end.  A
  real frontend's fetch stalls at exactly that translation fault, so
  the consumer should treat the chain as complete-but-bounded, not
  defective.
* **Translation unavailable, first fetch.**  The excursion's *first*
  target cannot be fetched or translated, so the chain is empty and
  there is no :class:`WPBBEntry` to carry the marker; the condition
  rides the body entry itself and is emitted as a *chain-level*
  ``CST_WP_EVENT_TRANSLATION_UNAVAIL`` event.  An empty or truncated
  chain whose target is genuinely unmapped in the current address
  space is *correct output*, not a defect: a wrong-path fetch goes
  through the MMU, and a real frontend fetches nothing past a
  translation fault.  Wrong-path targets come from real static
  branch targets and observed indirect history inside the workload's
  text, so this is the exceptional case — and a *resident* target
  producing an empty chain indicates a plugin bug, which is why the
  exit summary counts ``WP first-TB unavailable`` separately and
  ``CST_WP_DIAG`` prints each instance with its refusal reason.
* **Containment bails.**  The sandbox's soft-budget overflow (a
  garbage-size speculative store — a real CPU's wrong path would
  fault and recover), the stuck-PC / no-forward-progress guards, the
  nop-slide cap on an unsealed BB growing far past any real block,
  and the poison early-out all drop the *in-flight accumulator* and
  end the chain; WP BBs already committed are preserved.  These
  chains look like early budget ends on the wire.
* **Flush re-run.**  A ``tb_flush`` that unwinds a spec-mode
  ``exec_tb`` before its guest instruction ran never reaches the
  wire: the walker signals the caller, which discards the truncated
  chain and re-runs the whole excursion in the fresh code cache.
  The wire contract is exact-or-longer — a flush-shortened chain
  would be indistinguishable from a silent bug.

System-mode tracing
-------------------

Under ``qemu-system-<isa>`` the tracer targets one chosen *process*
inside the guest, not the whole machine.  A guest-issued marker
opens the window and pins it to that process's address space; the
trace then contains the pinned process's user-space execution plus
the kernel code it synchronously invokes (syscalls and faults),
while asynchronous interrupts — OS noise uncorrelated with the
workload — are excluded whole.  Everything in this section is
system-mode machinery; under ``*-linux-user`` the pin is a no-op,
the fault stack stays empty, and the async flag is always false.

.. _asid-pin:

Marker windows and the address-space pin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``trace_window=marker:simulation=N`` arms a guest-driven window.
The marker is a per-ISA byte sequence of provably-dead redundant
instructions — on x86, ``CST_MARKER_SEQ_LEN`` identical
``mov $CST_MARKER_MAGIC, %eax`` back to back; on the fixed-width
ISAs, a minimal two-instruction immediate-load pair repeated the
same number of times.  Rewriting the same register with a value it
already holds is work no compiler emits, so the sequence cannot
occur in real code by accident; and it needs no ELF symbols, no
host icount, and no guest-kernel modification.  ``vcpu_tb_trans``
arms an exec callback on every instruction whose bytes match a
marker word; the callbacks judge consecutivity at execution time by
user-space PC adjacency (same address space, user privilege, each
insn at the PC immediately after the previous one), so detection is
independent of how translation slices the sequence into TBs.

Marker detection is a correct-path fact, and the wrong path is
fenced out of it at the callback level by two independent gates:
the QEMU-side per-vCPU spec-mode flag
(``qemu_plugin_in_spec_mode()`` — the ground truth for the
*executing* vCPU, visible to a speculative invocation regardless of
which thread's TLS the callback reads) and the per-thread
``g_wp_state.in_progress`` session flag.  Speculation routinely runs
the marker bytes — the wrong path of a spin-wait branch falls
straight into the END sequence on every excursion — so an invocation
that leaked past the fence could advance the adjacency run, or
complete it, from wrong-path execution.  The callbacks stay
*registered* on every translation, spec-born ones included: the
fence is in the callback, not the registration, because suppressing
registration on wrong-path translations changes their
instrumentation shape and was observed (A/B on the SMP thread_test)
to livelock the guest at segment open through a QEMU-base
interaction.  ``CST_MARKER_DIAG=1`` prints every correct-path
marker-callback invocation (plus WP-gated and step-bail counters)
for triage.

The marker must execute *inside the target's own address space* —
it is compiled into the workload (or injected at its entry point),
never run by a launcher that then ``execve``\ s, because ``execve``
replaces the address space and would leave the pin on the
launcher's.  When it fires, the plugin captures the executing
vCPU's address-space ID (``qemu_plugin_get_addr_space_id()`` — CR3
on x86, SATP on RISC-V, TTBR0 on Arm, the MIPS ASID), stores it as
the **pin**, and opens a segment of ``simulation`` instructions.

The pin defines both the trace filter and the window clock:

* **Privilege 0 at the pinned ASID** is the ground truth for "the
  workload's own instruction".  Those instructions are traced *and
  counted*: the window budget, the progress heartbeat, and the
  finish report all run on this user-instruction clock, so a
  marker-mode window covers the same user-space instructions a
  user-mode run of the workload would.
* **Kernel execution at the pinned ASID** (syscalls, fault
  handlers) is traced but *not counted*.  Its templates carry
  ``is_system``, stamped from the live correct-path privilege at
  execution time — authoritative over any wrong-path seed, because
  speculation can cross the privilege boundary and translate code
  in the wrong context — and serialized on every instruction
  descriptor as the ``SYSTEM`` flag bit.
* **Foreign address spaces** are neither traced nor counted: the
  PathBuilder's foreign-ASID boundary drops them (async excursions
  are suspended instead — see :ref:`async-exclusion`).

Two per-target refinements keep the pin honest about what the
address-space register can actually attest.  On RISC-V the highest
privilege level does not translate through the pinned register at
all — M-mode fetches bypass ``satp`` — so firmware handling a
synchronous SBI call executes while the register still holds the
pinned process's value.  Those TBs are firmware a level above the
OS kernel, not the process's kernel work, and the attribution path
drops them regardless of the ASID match (the ``kexc M-mode TBs
dropped`` stat).  On MIPS the pin is a bare ``EntryHi.ASID`` value
from an architecturally 8-bit space the OS recycles by generations,
so a rollover can silently re-assign the pinned value to a
different process; the synchronous ASID-write hook watches for the
pinned value returning after enough *distinct* other values to
imply the space wrapped, and answers with one stderr warning plus
the ``pin ASID reuse suspected`` stat — detection only, the pin
itself stays.

A workload shorter than its budget emits the **end marker** (the
same sequence shape, built on ``CST_MARKER_END_MAGIC``) just before
it exits.  Executed in the pinned address space, it closes the
window at that point — the "budget *or* program end" stop.  Closing
at the marker rather than at process teardown matters because a
freed ASID can be reused by another process and silently re-match
the pin; the finish line reports ``END`` rather than an underrun.

Segment opens in marker mode follow the same per-thread boundary as
every other mode: ``reset_segment_local_state`` runs once on the
opening thread (global stores plus its own TLS), and every other
vCPU thread resets its own PathBuilder, async state, and event
queue as it observes the bumped segment generation on its next
step — TLS cursors can only be reset from their own thread.

A mid-run open executes on one vCPU but activates **every**
vCPU's scoreboard (``is_active`` mirror plus the budget sentinel,
each ``is_active`` write followed by ``refresh_ctx_gates`` to stamp
the derived ``trace_this_ctx`` / ``pin_probe`` gates): on an SMP
guest the pinned process's threads run wherever the scheduler put
them, and a vCPU left inactive would silently carry no trace
coverage — and no user-clock contribution — for the whole segment.  The user-instruction clock's delta source is likewise
per-vCPU (each vCPU's fold reads its own ``insn_count`` cursor;
``user_count_reset`` seats the opener's cursor exactly and marks
every other vCPU's unprimed, so its first fold contributes zero
rather than its pre-pin backlog).

In every non-marker window mode the pin holds ``UNPINNED`` and the
whole machinery costs one relaxed atomic load per TB.

.. _fault-excursions:

Synchronous-fault excursions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Synchronous faults — page faults, TLB refills, lazy-enable traps —
are *kept*: the handler is real, workload-induced kernel code.  The
tracer's contract for them has two halves: handler code is emitted
first-class at its exception-nesting depth, and the faulting BB is
emitted **whole**, exactly once, after its excursions resolve.

QEMU owns the ground truth.  Each target's ``do_interrupt`` calls
``cpu_plugin_fault_push`` for a *re-executing* fault only (the
handler's exception return lands back on the faulting instruction;
syscalls and advance-past exceptions never push), pushing the resume
PC; each target's exception-return path calls
``cpu_plugin_fault_pop``, which pops only when the return target
equals the top frame's resume PC — an exact match, not a heuristic,
because a pushed fault always re-executes its faulting instruction.
Both chokepoints append the corresponding ordered event, and both
are no-ops on the wrong path.  ``plugin_fault_depth`` is the live
nesting depth.

On the plugin side, each drained ``FAULT_ENTER`` is classified
against the deferred prev (see :ref:`path-builder`):

* **Case (a) — re-fault.**  The resume PC matches an in-flight
  frame ``{resume_pc, asid}``: the same instruction faulted again
  (a TLB refill followed by the demand fault is *one* faulting
  instruction).  The deferred prev's accumulated pieces join that
  frame; the anchor is recorded once.
* **Case (a2) — second fault, same block.**  The resume PC is new,
  but the faulting TB is a byte-identical subrun of an in-flight
  frame's template and the new resume PC lies inside that template:
  a *later* instruction of the same pending block faulted (the
  archetype is a load's demand-zero fault followed by a store's CoW
  fault in one BB — the resume suffix re-executing after the first
  fault is a subrun of the frame's own template by construction).
  The piece joins that frame — anchors and accumulators extend —
  and the frame re-keys to the new resume PC so the eventual
  completion matches the final suffix.  Minting a second frame
  keyed at the first resume PC instead would drop every instruction
  ahead of it from the merged emission and leak the original frame.
* **Case (b) — new fault.**  The resume PC lies inside the deferred
  prev: prev *is* the faulting BB and its terminating branch never
  ran.  It is folded into a serializable template (force-committing
  an incomplete head if needed) and a fresh context frame absorbs
  its memops, register snaps, and the faulting-instruction anchor.
* **Case (c) — successor substitution.**  The resume PC is in
  neither: the fault hit a block whose exec callback never ran (an
  instruction-fetch miss on prev's successor, or a resume suffix
  re-faulting before its own callback).  No frame is minted, but the
  TB executing now is the fault *handler* — not where prev's control
  flow went — so the seal substitutes the entry's resume PC for the
  scoreboard's ``current_pc``: that PC is the architectural
  successor (the fetch the CPU attempted after prev and re-executes
  after the excursion).  Sealing against the handler instead would
  record the handler's entry PC as a taken conditional's target
  (breaking the decoder's chain walk at the real target), flip a
  fall-through fetch-miss's direction to "taken", and poison an
  indirect branch's observed-target pool with the handler PC.  Only
  entries taken outside an async window qualify — an in-window fault
  is excluded handler content, and the async machinery already seals
  prev against the window's departure PC.

A ``FAULT_RETURN`` marks its frame returnable, but emission rides
the resume suffix's *seal*, one or more steps later: when a sealed
BB starts at a frame's resume PC, the merge re-injects the frame's
accumulated pieces ahead of the suffix's own, emits the **full**
template once with the suffix's resolved branch, and retires the
frame.  A returned frame matches by event identity; a frame whose
return was never observed (a non-LIFO guest return — a context
switch inside a blocking fault resuming the outer task first)
completes on a byte-content check alone.  The content check is what
keeps a same-VA frame from *another* address space — reachable
through ASID reuse, since every process maps code at the same low
VAs — from swallowing an innocent block's seal.

On the wire (``CST_FLAG_FAULT``, set in marker mode; user-mode
traces carry no trailer): every CP entry carries ``fault_depth``
(0 = normal code, ≥1 = handler code at that nesting level,
baselined per segment).  User-privilege entries always stamp 0:
user code is never handler content, but a preemptible kernel can
context-switch inside a blocking fault handler and resume another
guest thread's user code while the interrupted task's frames are
still live on the vCPU's per-CPU fault stack — the clamp keeps
that depth from leaking onto the resumed thread (its *kernel* work
keeps the raw-baselined depth, an accepted approximation of the
per-vCPU stack).  A merged faulting BB carries
``fault_anchors`` — the faulting-instruction indices, one per
excursion, in order.  Consumers replay the handler at its depth and
see the faulting block once, whole, with its detour points marked.
Three environment toggles support A/B diagnosis: ``CST_NO_FAULT``
(marker mode runs without the fault feature), ``CST_NO_FAULT_MERGE``
(depth stamping without classification/stash/completion), and
``CST_NO_FAULT_WP`` (merged emits carry no wrong path).

.. _async-exclusion:

Asynchronous-interrupt exclusion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Asynchronous interrupts — timer ticks, device IRQs, the scheduler
activity they trigger — are not induced by the traced workload, so
the entire delivery-to-return excursion is excluded from the trace.

QEMU marks the window: the target's exception-delivery path sets a
per-vCPU flag on an *asynchronous* entry and records the
interrupted PC (the **departure PC**, where the handler's return
will resume); the fetch loop clears the flag when execution returns
to exactly that PC.  The pairing is robust to the scheduler
context-switching away mid-handler and to nesting (the outermost
departure PC is kept).  Both edges also produce ordered
``ASYNC_ENTER`` / ``ASYNC_RETURN`` events.

While the window is open the PathBuilder suspends: excluded TBs
never step, the pending seal stays untouched — so the resume TB
later seals the interrupted branch against its *real* target, with
no phantom edge through the handler — and the per-thread
``g_capture_mute`` latch drops the handler's memops, register
snaps, and synthetic-EA loads at their capture sites (left
unmuted, a handler's captures would attach to the interrupted user
BB's slots: kernel addresses collapsing onto instruction 0 of a
user block).  The suspend deliberately precedes the foreign-ASID
boundary: an async excursion routinely context-switches through
other address spaces, and those TBs must take the
prev-preserving suspend, not the prev-dropping ASID gate.

A window can be abandoned — the departure PC is never fetched
again (the guest scheduler handed the vCPU to another thread of
the pinned process, the interrupted task was killed, or a signal
rewrote its resume point).  The recovery is definitional: the
pinned process observed at *user privilege* cannot be handler
content, so the window force-closes there
(``qemu_plugin_async_int_reset`` plus the local mute reset; no
``ASYNC_RETURN`` event exists for it, and a later fresh
``ASYNC_ENTER`` opens a well-formed new window).

An abandoned window is precisely a control transfer the exclusion
hid, so the TB observed at the recovery is *not* the deferred
prev's successor — on an SMP guest it is routinely another guest
thread of the same process, and sealing the interrupted branch
against it would fabricate a cross-thread taken edge (and, through
the template's last-write ``taken_pc``, relabel every prior taken
count with the foreign target).  The recovery therefore seals the
deferred prev against the window's **departure PC** — where the
interrupted flow architecturally resumes, read from the retained
outermost ``ASYNC_ENTER`` event — making the abandoned-window seal
identical to the one a proper resume would have produced.  When no
departure PC is known (a window latched from live state before the
segment's first prime), the deferred prev is dropped like the
foreign-ASID boundary drops it, accumulated captures included.

.. _time-transparency:

Guest-time transparency
-----------------------

Plugin work runs on the vCPU thread but is not guest execution, so
its host wall-clock cost must never be charged to guest time.  The
stakes are highest in system mode: if one guest timer-tick
handler's instrumented cost exceeds the tick period, the next tick
is already pending when the handler returns and the guest collapses
into a self-sustaining tick/scheduler storm (RCU stalls, zero
foreground progress).  Three cooperating layers keep the guest's
clocks clean; all are no-ops in user mode, and the QEMU side of
each is catalogued in :doc:`qemu_modifications`.

* **Per-callback vclock freeze.**  ``VClockPauseGuard`` wraps the
  CP step in ``vcpu_tb_exec`` and the translation work in
  ``vcpu_tb_trans`` with ``qemu_plugin_vclock_pause`` / ``resume``
  — a nesting-depth freeze of the guest virtual clock, so
  arbitrary instrumentation regions compose.  Because the CP step is
  gated on ``trace_this_ctx`` (see :ref:`cp-flow`), the freeze wraps
  only genuinely-owned pinned content: a foreign TB never dispatches
  the heavy callback, so its execution stays on the guest clock and a
  foreign-process storm cannot throttle guest time.
* **Whole-excursion freeze for the wrong path.**  The WP session
  boundary (``wp_enter_spec_session`` / ``wp_end_spec_session``)
  pauses guest virtual time for the entire excursion via
  ``qemu_plugin_spec_vtime_pause`` / ``resume`` — at the *outer*
  boundary, not per spec-mode entry, so a fault-skip's spec-mode
  teardown/re-entry cannot leak ticks.  On excursion exit the QEMU
  base re-syncs register-coupled host timers (the Arm generic
  timer, the RISC-V/MIPS timer compare) to the rolled-back
  register state, so a speculative timer write or a mid-walk timer
  expiry cannot park a one-shot host timer dead.
* **The x86 TSC pin.**  x86 guests read two clock families (TSC
  and HPET-class devices) and their watchdog cross-checks them;
  the QEMU base locks the guest TSC to the guest virtual clock at
  each resume with a once-calibrated frozen ratio, and holds the
  BQL across each wrong-path excursion, so the two clocksources
  cannot skew regardless of how often excursions cycle.

The virtual-clock freeze covers wall-clock-driven time only.  Under
``-icount`` the virtual clock is driven by the instruction count,
which a tick freeze does not stop, so wrong-path instructions leak
into guest time; the plugin warns once at install when wrong-path
simulation is enabled together with ``-icount`` (the trace is
valid; guest timing may be perturbed).

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
``cst_pc_is_poisoned`` at the top of each iteration (excursion entry
excepted — see :ref:`wp-flow`) and abort before re-translating the
address.  When poisoning fires inside the main binary's text segment
(``[qemu_plugin_start_code(), qemu_plugin_end_code())``) the plugin
emits a one-shot SMC-suspect warning to stderr — that is the actual
self-modifying-code signal.  Out-of-text-segment poison fires
silently because the symptom is "WP wrong-pathed into data," which
is normal speculative behaviour the tracer just refuses to record.

Both the byte-memo and the poison set **persist across**
``vcpu_tb_flush``: a flush is JIT housekeeping, so SMC detection
must survive it, and a legitimate flush-plus-retranslate of
unchanged code re-matches its first sighting (no false poison) and
reuses its template.  Staleness is handled by content, not by
lifetime:

* **Poison entries carry a content hash.**  Each entry stores a hash
  of the whole TB's canonical byte image at verdict time.  Virtual
  addresses are reused across address spaces (static binaries map at
  the same base), so a poison earned by one process's bytes must not
  refuse another process's wrong-path target at the same VA: a
  spec-mode translation whose bytes no longer match the stored hash
  proves different content lives there now and self-clears the
  entry.
* **The correct path heals.**  Correct-path execution reaching a
  poisoned PC is proof the verdict no longer holds — the CPU really
  is executing that code — so a CP translation erases poison for
  every canonical VA it covers and refreshes the byte-memo to the
  CP-observed word (in system mode the same VA legitimately reads
  different bytes across CP translations: demand paging, ASID
  reuse).
* **Spec mode only reads.**  A wrong-path translation never mutates
  the persistent state: a spec read of a mid-refill page or a
  foreign address space's bytes must not seed the first-sighting
  word or park a permanent poison that would block the correct path.
  The WP walker tracks its own transient poison in an
  excursion-local set.

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
destructors run.  By the time ``plugin_exit`` fires, C++ containers
in plugin globals may already have been destroyed, so the plugin
mirrors the relevant cardinality counts as raw ``uint64_t`` in
``g_stats`` (``tb_templates_created`` etc.) and bumps them at
insertion time, so the exit-time summary still reports useful numbers.

*Immortal process-wide aggregates.*  The stores the vCPU callbacks
touch (``g_template_store``, ``g_branch_history``, the poison /
byte-memo maps, the scoreboard) are deliberately never destructed:
``exit(0)`` at a segment close runs static destructors on the closing
vCPU thread while, on an SMP guest, the *other* vCPU threads are
still executing — a survivor inside ``vcpu_tb_trans`` scanning a
just-destructed template store is a straight SIGSEGV.  The process is
exiting, so reclaiming these containers buys nothing; a shutdown gate
at the top of ``vcpu_tb_trans`` (translation is not ``is_active``-
gated) additionally stops surviving vCPUs from doing pointless
template work while the process dies.

*Thread-locals at exit.*  The CP memop accumulator is a TLS vector.
On REP-heavy workloads it can be MiB-sized and backed by a direct
``mmap``.  Forcing ``shrink_to_fit`` from atexit SIGSEGVs deep in
``__libc_free`` because some glibc heap state is already torn down by
that point.  ``cleanup_current_thread`` therefore only ``clear()`` s;
the TLS destructor runs the natural vector destructor afterwards.

*glib mutexes, not std::mutex.*  ``<mutex>``'s transitive include
chain pulls ``<cctype>``, which goes through QEMU's
``include/qemu/ctype.h`` shadow that breaks libstdc++'s
``using ::isalnum;`` declarations.  The plugin uses glib mutexes
everywhere to avoid that build-time hazard: ``GMutex`` for
``data_lock`` / ``unknown_warn_lock`` and ``GRecMutex`` for
``exec_lock`` (see `Synchronization summary`_ for why that one is
recursive).

*The trace is flush-invariant.*  A ``tb_flush`` is QEMU JIT
housekeeping — the code buffer filled and every TB re-translates —
not a guest-execution event, so the trace must be identical with or
without it.  Three mechanisms make that hold: CODE-class templates
are never freed and a re-translation reuses its existing chain
through the dedup index (see :ref:`template-lifetimes`); a flush
that unwinds a spec-mode ``exec_tb`` is detected via a monotonic
flush counter and the whole excursion re-runs in the fresh cache
(see :ref:`wp-termination`); and a flush raised *during* a
wrong-path translation is deferred by the QEMU base to the next safe
point after the walk unwinds (see :doc:`qemu_modifications`).  The
``vcpu_tb_flush`` callback itself only bumps the flush counter,
nulls ``g_wp_state.last_executed_tb`` (which may point at a
reclaimee), and reclaims SPEC-class templates.

*Segment-generation stale-fragment guard.*  Switching segments
calls ``clear_bb_map()``, which drops the owning ``unique_ptr`` s
so any ``BBTemplate*`` held in another thread's in-flight chain
dangles.  ``reset_segment_local_state`` bumps a monotonic
``g_segment_generation``; every chain stamps the generation on each
``append_fragment`` and self-resets on mismatch, so one thread can
reset segment-local state without reaching into other threads'
``thread_local`` chains.  Each thread's PathBuilder likewise resets
its own frames and pending-seal slot via ``on_segment_open`` as it
observes the bumped generation (TLS cursors can only be reset from
their own thread), and cross-segment references held by persistent
templates are ``SegRef`` handles that read as null once stale.

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
(speculative TBs carry the full callback surface), so
mem-callback-driven capture stays correct under speculation.

*Sibling TB translations never conflate.*  QEMU translates the same
start_pc more than once: different cflags (notably the wrong-path
simulator's ``CF_NO_GOTO_TB`` / ``CF_SINGLE_STEP`` translations) or
a flush + retranslate.  ``tb_templates_`` is a vector, not a
start_pc-keyed map, and the dedup index keys on ``(start_pc,
canonical insn count)``, so siblings of *different length* — a
full-BB correct-path TB vs a wrong-path TB that entered mid-block —
each keep their own fragment chain, while a sibling of the *same*
shape reuses the existing chain rather than duplicating it.  The
per-TB exec-cb ``udata`` always points at a chain whose shape
exactly matches the just-executed QEMU TB.  For real binary code the
canonical-insn arrays are identical across same-shape siblings (the
static bytes don't change), so the splitter produces the same
fragment shape every time and the chain assembler folds it
deterministically.  When the bytes *do* appear to change — the
dynamic-memory speculation case — the poison detector (see
:ref:`poison-detection`) catches it at translation time and refuses
to materialize the fragment at all.

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
   * - ``exec_lock`` (``GRecMutex``)
     - Held across the CP step in ``vcpu_tb_exec`` so path state,
       chain assembly, window management, emission, and any
       synchronous WP simulation all serialize.  Also held during
       ``plugin_exit``, the marker open/close callbacks, and the
       budget threshold handler.
   * - ``data_lock`` (``GMutex``)
     - Mutates the template stores (``tb_templates_``, ``bb_map_``,
       the dedup indexes), the byte-stability / poison maps
       (``g_first_insn_word``, ``g_poisoned_pcs``), the chain
       assembler's fragment list, and ``g_branch_history``.  Acquired
       briefly inside the larger ``exec_lock`` window (and by
       ``vcpu_tb_trans`` / ``vcpu_tb_flush``, which run without
       ``exec_lock``).
   * - ``unknown_warn_lock`` (``GMutex``)
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

``exec_lock`` is a *recursive* mutex because plugin callbacks can be
re-entered on the same thread mid-step: a TCG code-buffer flush
during wrong-path simulation dispatches plugin callbacks
synchronously (``tb_gen_code`` → ``qemu_plugin_flush_cb``) while the
thread is already inside ``vcpu_tb_exec`` holding the lock, and a
non-recursive mutex self-deadlocks there.  ``exec_lock`` is never
paired with a condition variable, so the recursion is safe.  The
WP-mode early-out in ``vcpu_tb_exec`` deliberately runs *before* any
lock acquisition — the nested spec-mode invocation must not run the
CP step against wrong-path state.
