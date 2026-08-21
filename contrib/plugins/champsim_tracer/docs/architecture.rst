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

The numbers below are measured tracing ``qemu-x86_64 -seed 1
-B 0x400000 /usr/bin/sha256sum`` over a fixed 5 MiB input, 14.5 M
architectural instructions of capture (x86_64 host, Intel Xeon
Ice Lake-SP).  They are representative of this workload only; other
workloads vary in both runtime and trace size.  Raw size is the
uncompressed ``.cst`` container; the xz column recompresses the same
members with ``xz -T0`` (the codec the tracer runs in-process when
``compress=`` is set).

.. list-table::
   :header-rows: 1
   :widths: 38 12 12 12 12 14

   * - Configuration
     - Wall (s)
     - Raw size
     - xz size
     - B/insn raw
     - Slowdown
   * - bare ``qemu-x86_64`` (no plugin)
     - 0.13
     - n/a
     - n/a
     - n/a
     - 1× (baseline)
   * - ``wp=0,memdata=0,regdata=0``
     - 1.48
     - 3.24 MiB
     - 217 KiB
     - 0.23
     - 11×
   * - ``wp=1,memdata=0,regdata=0``
     - 4.21
     - 17.0 MiB
     - 830 KiB
     - 1.23
     - 32×
   * - ``wp=1,memdata=1,regdata=0,wp_memdata=0``
     - 4.50
     - 17.6 MiB
     - 1.04 MiB
     - 1.27
     - 35×
   * - ``wp=1,memdata=1,regdata=1``
     - 9.11
     - 106 MiB
     - 57.1 MiB
     - 7.62
     - 70×

Reading the table:

* **Slowdown vs bare QEMU:** tracing without WP costs ~11× on this
  workload because every TB pays a ``vcpu_tb_exec`` callback +
  Capstone-classification + chain-assembly walk.  Enabling WP
  simulation raises it to ~32× because every CP branch triggers a
  separate TCG re-entry for the speculative side-trip.  Adding
  ``regdata=1`` roughly doubles it again — every instruction's
  destination registers are read out via
  ``qemu_plugin_read_register``.
* **Trace size:** the field-delta encoder is compact for addresses.
  CP-only addresses produce ~0.23 bytes/insn raw and compress ~15×.
  The full configuration (CP+WP, all data, all reg snaps) lands near
  7.6 bytes/insn raw.  Compression is workload-dependent: the
  address-bearing rows compress 15–21× under xz, but this workload's
  register data is SHA hash state — near-incompressible — so its
  full-capture row compresses under 2×.  A workload with lower-
  entropy register values compresses several times better.
* **Memory footprint:** the plugin's RSS grows roughly with the
  template-cache size (one ``BBTemplate`` per static basic block,
  on the order of a few hundred bytes each) plus the WP simulator's
  speculative-store buffer (bounded by ``wpdepth`` × the workload's
  store rate).

Workload-dependence caveat: ``sha256sum`` has a tight compute kernel
that delta-encodes well but produces high-entropy register state.
Branch-heavy workloads push more bytes per instruction on the
control-flow fields; memory-bound workloads with diverse access
patterns inflate the data-bearing configurations further.  Run
``cst_audit`` on a representative slice of your own workload before
sizing storage for a long run.

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
  that both compressors handle well — measured ratios on the workload
  above range from ~15× (CP-only addresses) under ``xz -T0`` down to
  under 2× when the capture carries high-entropy register data (this
  workload's SHA hash state); most workloads sit toward the high end.
  The in-memory trace size is unchanged but the on-disk footprint
  shrinks substantially.
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
* **``field_id`` to slot via an 8192-entry LUT.**  Power-of-two sized
  to cover the whole well-known FID space at the 512-slot ceiling
  (the largest slotted field-id is ~7180); the LUT replaces an
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
  user-mode trace each guest thread is its own host thread — qemu-user
  gives every ``clone`` its own ``CPUState`` — so ``thread_id`` is that
  thread's index and there is no scheduler multiplexing behind it.  In a
  **system-mode** trace, pinned or not, the id is resolved from the
  guest kernel's per-thread pointer register (x86-64 ``FS.base``,
  AArch64 ``TPIDR_EL0``, RISC-V ``tp``, MIPS CP0 ``UserLocal`` —
  :c:func:`qemu_plugin_get_thread_ptr`) and mapped to a compact id in
  first-sighting order within the segment.  Because that pointer follows
  the software thread, the id is **stable across vCPU migration**: a
  thread the guest scheduler moves between vCPUs keeps one
  ``thread_id``, and two threads time-slicing a single vCPU are two
  distinct ids — the opposite of a vCPU index, which would split the
  first and merge the second.  A single-threaded traced process is
  ``thread_id`` 0 regardless of which vCPU(s) it ran on.  Each segment's
  body opens with an explicit ``BODY_TAG_THREAD_SWITCH`` naming the
  starting thread; the per-segment thread-id map is reset at each open.
  *Degradation:* a target/model whose thread-pointer register is never
  written (no MIPS ``Config3.ULRI``, a guest that sets no TLS) reports
  0 for every thread, so its threads collapse to one id — honest
  indistinctness, never a fabricated identity.  For kernel-side
  attribution see :ref:`single-address-space`.
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

Address-space scope and per-thread attribution (system mode)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A system-mode trace keys memory by ``(asid, virtual address)``.  Every
body entry names both its software thread (``thread_id``) and its
address-space id (``asid``), and a ``BODY_TAG_ASID_SWITCH`` record rebases
the ASID dimension whenever the running address space changes — the
address-space id being the page-table base / ASID register (x86 ``CR3``,
RISC-V ``SATP``, Arm ``TTBR0_EL1``, MIPS ASID).  The same virtual address
in a different address space is therefore different memory, and the wire
disambiguates it.  *Which* processes are captured is the marker scope's
decision — the default ``policy=latch`` traces each marker-owning process,
``policy=trace-all`` every context — but the ``(thread, asid)`` context
rides every entry regardless.  With kernel page-table isolation off (the
canonical configuration), a process's synchronous kernel excursions share
that process's ASID, so kernel and user code of one process fold to a
single address space, told apart only by the per-insn ``SYSTEM`` bit.

Per-thread attribution of *kernel* code follows the guest scheduler, not
the vCPU:

* **User code is exact.**  ``thread_id`` is read from the per-thread
  pointer, a register the kernel context-switches, so a thread's
  user-space blocks carry one id wherever the guest scheduler runs them —
  stable across a migration.
* **Kernel code carries the CURRENT task.**  A syscall or fault handler
  runs as its caller and inherits that thread, which is what an excursion
  should look like.  But a context switch performed entirely inside the
  kernel hands the rest of the strand to the incoming task, and the
  producer follows it: on x86-64, AArch64 and MIPS the thread-pointer
  register still names the current task at kernel privilege (Linux
  reloads it from the incoming task in ``switch_to()`` and touches it
  nowhere else), so the sample is taken at every privilege level and the
  strand retags itself at the switch.  A freshly cloned child finishing
  its return path before it has ever run a user instruction is the child,
  not its parent; a kernel thread scheduled in on a borrowed mm is
  itself, not whoever last returned to user on that vCPU.

The property this preserves is **strand sequentiality**: filtered to one
``(thread_id, asid)`` context, the entries read as a single instruction
stream in order.  The validator asserts it directly — see the
``thread_strand`` check in :doc:`validator`, which fails a trace in which
two concurrent streams braid inside one context.

RISC-V is the documented exception (:ref:`kernel-strand identity
<limits-kernel-strand>`): its trap
entry repurposes ``tp``, so only user-privilege samples are trusted there
and kernel code is attributed to the thread that entered the kernel on
that vCPU — correct while a process stays put, wrong for work left on a
vCPU it has migrated off.  Pinning keeps a RISC-V trace inside that
envelope: :program:`cst_attach` confines the target to one guest CPU by
default (``--pin-cpu N`` / ``--no-pin``), and ``taskset`` / ``isolcpus``
do the same for a compiled-in marker.  When a segment observes the traced
process running **user** code on more than one vCPU — the architectural
migration signal — the plugin emits **one** stderr warning per segment,
making the exposure loud rather than silent.  The per-vCPU kernel-nesting
discipline the validator's
``syscall_fault_nesting`` check asserts is relaxed at the migration seam
for the same reason (a documented boundary, verified by the
forced-migration test, not a papered-over defect).

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

A chain does not always reach its terminating branch.  Control can
leave the block part-way — an async window swallows the rest of a true
BB and execution resumes somewhere unrelated, a foreign address space
intervenes, a segment boundary bumps the generation — and the next
fragment then does not continue the chain.  Those fragments **executed**,
so the walk seals the chain at the extent that ran and emits it, ahead
of its own blocks, in program order; it does not discard it.  The
sealed block goes through the same cut-short store the segment close
uses (``commit_partial_bb``), so it can never be confused with the
complete block at the same address, and it carries its own slice of the
positional register-snapshot sink: the sink is a FIFO shared with the
blocks that follow, and a chain dropped without its snaps left them
behind as the next block's "leaked prefix", which the emit-time
backstop then "recovered" by trimming — a misattribution dressed as a
repair.  On a migration/fault workload this is not a corner: one cell
sealed 1033 such blocks carrying 4118 instructions that used to reach
nothing.

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
       the fault-excursion identity ledger, and the seal /
       continuation / emit decision.  See :ref:`path-builder`.
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

.. _sysreg-operands:

System and control registers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every other register reaches the plugin as a Capstone register id and
resolves through ``<isa>_reg_class[]``.  System registers cannot, for
two separate reasons.  They are numbered in a space of their own — an
AArch64 ``mrs`` operand carries the packed ``op0:op1:CRn:CRm:op2`` word
(``NZCV`` is ``0xda10``, while the ordinary ``AARCH64_REG_NZCV`` is
``5``), and a RISC-V Zicsr instruction carries a bare 12-bit CSR number
in what is architecturally an immediate field, so indexing the register
table with either would read the wrong row or run off its end.  And,
more decisively, Capstone mostly has no register id to offer: of the
1214 entries in its ``aarch64_sysreg`` enum exactly two, ``NZCV`` and
``FPCR``, have a same-named ``aarch64_reg``.  ``TPIDR_EL0`` — read by
every TLS access, and 45 of the 50 ``mrs``/``msr`` sites in a
hello-world static binary — has none, nor does any EL1 control
register.

So the translation cannot be done by renumbering, and it is done where
every other Capstone gap is closed: at the boundary.  ``disas/capstone.c``
resolves the operand's architectural ROLE and emits a
``QEMU_PLUGIN_OP_SYSREG`` operand carrying it in ``sysreg_class`` —
``QEMU_PLUGIN_SYSREG_FLAGS``, ``_FPCTRL``, ``_VECCTRL``, ``_THREADPTR``
or ``_OTHER``.  ``reg_id`` still carries the raw architectural encoding
for identification, but nothing classifies from it.  The plugin side is
then ISA-independent: ``generic_reg_for_sysreg_class()`` renames the
role into a generic ID, with no per-ISA branch and nothing to keep in
step with an ISA table.  Two consequences are worth stating:

* **Direction comes from the boundary, not from Capstone.**  Capstone
  leaves the AArch64 system operand's access bits empty and reports
  every RISC-V CSR operand as read-modify-write.  ``disas/capstone.c``
  fills the access from the instruction form instead: ``MRS`` reads and
  ``MSR`` writes (the operand's own ``sysop.sub_type`` says which), and
  Zicsr follows its suppression rules — ``csrrw`` with ``rd == x0``
  does not read, ``csrrs``/``csrrc`` with a zero ``rs1`` does not
  write.  Getting that wrong is not cosmetic: reporting ``csrr a0, vl``
  as a write of ``vl`` would reroute every following vector
  instruction's configuration edge onto it.

* **The mapping is deliberately not one slot.**  ``REG_SYS`` takes the
  long tail, but the registers with their own dependency populations
  get their own IDs — ``REG_FLAGS`` for AArch64 ``NZCV`` (so an ``msr
  nzcv`` and the ``b.eq`` after it meet), ``REG_FCSR`` for the FP and
  fixed-point control words, ``REG_TLS`` for the thread pointer,
  ``REG_VCTRL`` for the RISC-V vector configuration.  A dependency edge
  onto a register the instruction never touched costs a consumer as
  much as a missing one; :doc:`reference` records the reasoning per ID.

The rule that decides where a control register lands is *what would
alias what*, not what the manual calls it.  Two registers share an ID
when a consumer ordering one against the other is right, and get
separate IDs when it is not:

* RISC-V ``vl`` and ``vtype`` share ``REG_VCTRL`` because a ``vsetvl``
  writes them as a pair and every vector instruction reads both — no
  edge exists between them that the shared ID invents.
* ``vxrm`` and ``vxsat`` do **not** join them.  They are ``vcsr``'s
  fields — a rounding mode and a status flag for the arithmetic unit,
  which is what ``REG_FCSR`` already means — and a saturating op writes
  ``vxsat`` without touching ``vl``, so on ``REG_VCTRL`` every one of
  them would appear to redefine the vector length its neighbours read.
* ``vlenb`` is read-only — VLEN in bytes, which nothing writes — so it
  sits in ``REG_SYS`` with the identification registers rather than
  taking a false edge from the last ``vsetvli``.

An ISA whose system registers Capstone does surface as ordinary
registers needs nothing here: MIPS names its coprocessor registers
``MIPS_REG_COP0``\ *n*, so they resolve through ``mips_reg_class[]``
like any other register and never produce this operand type.  Should a
Capstone bump grow ``aarch64_reg`` or ``riscv_reg`` ids for the system
registers, the same becomes true there and the boundary tables shrink
to nothing.

One consequence reaches the tooling.  A system register's dependency is
recorded at the granularity of its generic ID, so the decode gate and
the implicit-operand table compare AGAINST THAT CLASS, not against the
architectural name: ``mrs x0, nzcv`` reads ``REG_FLAGS``, and the fact
that it was spelled ``NZCV`` rather than ``PSTATE`` is not a dependency
fact.  ``tools/implicit_audit.py`` carries the name-to-class
correspondence in its ``ACCEPT`` table; a register newly given a class
needs its name added there.

.. _cp-flow:

Correct-path flow
-----------------

``vcpu_tb_exec`` fires once per executed TB.  It is registered as a
conditional callback on the scoreboard's ``trace_this_ctx`` slot — a
bare ``is_active`` mirror — so the JIT skips the dispatch entirely
between segments; foreign-ness within a segment is the content-gate
bit, tested inside the step.  Its ``udata`` is the head fragment of the TB's
per-translation fragment list.  The callback has two layers: a short
shared prologue, then the PathBuilder step.

``trace_this_ctx`` stays a bare ``is_active`` mirror: the heavy step
must keep dispatching for non-gated contexts too, because the
any-context termination bounds (the stall ceiling, the idle-backstop
beat) ride it — a guest whose traced process is dead executes nothing
*but* foreign TBs.  Foreign-ness itself is the per-vCPU **content-gate
bit**, computed event-driven and tested as one relaxed load inside the
step.

The gate is one cached bit per vCPU.  At each committed address-space
change the tracer re-reads the marker sequence's bytes at each latched
window vaddr through the live context; a context that maps them is
traced, and every thread inside it is traced — borrowed-mm kernel
threads included.  No page-table root, ASID or process id is ever
stored or compared as an identity; the thread id only labels strands
on the wire.  There is no re-bind rule because there is nothing to
re-bind: recycling, migration and narrow-ASID identity are
non-concepts under content gating.

The wire's address-space naming is a LABEL: the compact asid index is
allocated from the live architectural value observed at each gate
refresh that evaluates on (never on the emit path, which reads the
per-vCPU carry).  Both the gate bit and the label carry are maintained
event-driven (``refresh_ctx_gates`` / ``marker_gate_refresh``): at
every ``is_active`` edge, at each committed address-space write, at
window opens/releases and at vCPU init — never on the per-TB path.

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
    the shared seal walk, continuation completion, emission.  See
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
    the previous TB normally.

    The icount and simpoint closes defer once further, by a whole
    step.  The window clock is bumped by a per-TB inline add at TB
    *entry*, so the crossing that arms the close is observed with the
    dispatching TB's instructions already counted — while that TB has
    not run: the step has only just promoted it into the pending-seal
    slot, its memory callbacks have not fired and its destination
    registers have not been snapped.  A close taken at that step's
    tail would flush that TB out of the slot ahead of its own
    execution, against empty accumulators, and the segment's last body
    entry would carry no memory operands and no register deltas.  The
    first satisfied visit therefore only *arms*; the close runs at the
    tail of the next step, by which time the budget-crossing TB has
    executed and the ordinary seal walk has emitted it exactly like
    every other entry — memops, register deltas, resolved terminal
    branch, wrong path.  The slot at that point holds the *next*
    dispatching TB, which the flush must not walk, so the deferred
    window close passes ``flush_final(walk_prev=false)`` and finalizes
    the in-flight chain only.

    The **END marker** defers to a true-BB boundary too, and for the
    same reason, but it needs no second armed step: the marker fires
    from inside its own instruction's callback, so its block has
    already begun executing when the arm is raised, and the first
    boundary the arm survives to *is* that block's own.  One armed step
    more would put a block past the END on the wire.  See
    :ref:`unsealed-at-close` for the ruling and its reason.

    The closes the guest's own progress raises where it stands —
    process exit, the dead-latch sweep, the stall ceiling — cannot
    defer: they fire on a TB that has run, and walk the slot as usual.

**The seal walk** (``collect_finalized_bbs``; shared by the per-step
seal, the fault-continuation seal, and the segment-final flush) walks the
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
  address space cannot bridge its fragments across the gap, so the
  deferred prev *departs the traced flow* there and is emitted at that
  moment, at its measured extent, with its terminating branch honestly
  unresolved (see :ref:`emit-at-departure <emit-at-departure>`).  The
  async mute suspend runs *first*: an async excursion routinely
  context-switches through foreign address spaces, and those TBs must
  take the mute suspend (which leaves the pending seal untouched for
  the resume), not the ASID-boundary departure.
* **The pending-seal swap.**  On ``CONTINUE`` the current TB is
  promoted into the pending-seal slot and the old occupant becomes
  the TB the seal phase walks, together with the fault depth stamped
  when it *executed* (the fault stack may pop between a TB's
  execution and its emission one step later; a seal-time read would
  lose the handler's level).

``step_seal`` (post-window, only on steps that survived the
shutdown / active / segment-boundary gates) applies the retained
fault events exactly once, then runs the shared seal walk:

* **Depth pipeline.**  The fault depth the current TB runs at
  is the count of un-returned fault-ledger entries — the live entries in
  ``frames_`` — that the *executing guest thread itself* entered.  It is
  deliberately **not** derived from the per-vCPU ``plugin_fault_depth``.  That stack is a
  single object shared by every guest process, and under multi-process
  churn it interleaves the pinned process's frames with a busy boot's
  leaked frames (a non-LIFO guest exception return — a context switch
  inside a blocking fault resuming the outer task first — never pops
  its frame, so a boot leaves dozens on the stack, observed near the
  64-slot cap) and the churn tasks' transient frames.  No single
  per-vCPU baseline scalar can partition those: a foreign frame popping
  drags a subtractive baseline down and a later foreign push then
  over-counts the pinned depth, while a context switch *through* the
  pinned handler and back under-counts it — the two churn signatures a
  raw-minus-baseline scheme produced (a faulting BB stamped at
  its own handler's depth, and a handler depth jumping ``0 <-> 2``
  across a kernel spin loop).  ``frames_`` holds exactly the pinned
  process's in-flight faults: foreign TBs are excluded and async
  excursions mute-suspended *before* they reach the classification, so
  neither ever seeds a ledger entry (a foreign span's departure emits
  only the pinned process's own deferred prev, never a foreign
  excursion — see :ref:`emit-at-departure <emit-at-departure>`), and
  the boot's leaked frames predate
  ``frames_``,
  which ``on_segment_open`` clears.  Counting its un-returned frames
  therefore yields the pinned nesting depth directly — ISA-agnostic,
  immune to the shared stack's pollution, and ``0`` on the fault-free
  user path (``frames_`` empty).  A returned frame's handler has
  already unwound (its ``FAULT_RETURN`` was observed), so it drops out
  of the count immediately even though its continuation (the resume
  suffix's seal) is still pending.  ``raw_depth_`` tracks the last
  event's ``depth_after`` for the ``CST_DEPTH_DIAG`` log only.

  **Frames are owned per guest thread.**  ``frames_`` is per-vCPU, and a
  vCPU multiplexes guest threads, so the ledger alone cannot say whose
  excursion a frame is: a thread the guest scheduler puts on this vCPU
  while a *peer* thread sits inside a fault handler would inherit the
  peer's nesting, and would step back down to its own level — with no
  unwind in between — the moment it was rescheduled after the peer's
  return.  Each ``CtxFrame`` therefore records the guest thread that
  entered the excursion (``CtxFrame::tid``, the identity the faulting
  block itself is emitted with), and three places consult it: the depth
  stamp counts only the executing thread's own frames, the pinned-user
  leak sweep retires only the frames of the thread whose user code proves
  it is at depth ``0``, and a completion's leaked-deeper sweep retires
  only same-thread ledger entries, sparing frames a peer put above it
  on the ledger — those nest concurrently, not inside.  This is what ``fault_depth`` is defined to
  mean (:doc:`format` §4.2a): the depth *this* basic block executed at.  A thread that *migrates* across vCPUs mid-excursion
  leaves its frames behind on the vacated vCPU and is counted at depth
  ``0`` on the new one — the documented single-core-pin scope boundary,
  the same one the migration warning names; ownership prevents a thread
  from inheriting a stranger's depth, it does not move an excursion
  between ledgers.  Where the target cannot vouch for the thread pointer
  in the context at hand — RISC-V M-mode firmware and H-extension
  virtualization, the two states the per-sample
  ``qemu_plugin_thread_ptr_tracks_current`` still answers no in — kernel
  code inherits the entering thread's identity and its frames with it:
  the KERNEL-STRAND degradation described in :doc:`limitations`,
  unchanged here.

  The stamp is taken **twice per seal**, because the seal moves
  ``frames_`` twice: the event drain at its head pushes new frames and
  marks returns, and the seal walk at its tail *retires* frames (a
  completion erases the completing frame and retires any leaked
  same-thread deeper entries).
  The current TB is promoted between those two movements, so a single
  head-only stamp gives the block that follows a completed faulting BB
  the *pre*-completion count.  That is invisible while every
  ``FAULT_RETURN`` is observed — a returned frame is already out of the
  count — but a guest exception return that the host's strict-LIFO fault
  pop suppresses leaves its frame flagged in-flight right through its own
  completion, and the following block then carries one excess level per
  suppressed frame.  Re-taking the stamp after the walk gives that block
  the post-unwind depth a completion proves it runs at: the resume suffix
  only executes after the exception return.
* **Fault-entry classification.**  Each ``FAULT_ENTER`` is handled
  individually against the deferred prev — see
  :ref:`fault-excursions` for the three cases, the split emission each
  performs, and the identity ledger (``CtxFrame``) it maintains.
* **Seal, continuation, emit.**  The seal walk collects finalized BBs;
  if the first sealed BB is some ledger entry's resumed suffix, it is
  emitted as a *continuation* of that entry's template — the same
  ``template_id``, ``bb_start`` at the entry's cursor, the seal's
  resolved branch and wrong path — and the entry is erased; otherwise
  every finalized BB emits normally.

Segment opens reset the builder (``on_segment_open``): fault-ledger
entries are dropped (each is an identity record whose executed prefix
already reached the wire at its fault, so the drop loses no
instructions — and their templates point into the just-cleared
``bb_map_``), the pending-seal slot and retained events clear, the
depth pipeline zeroes and re-primes lazily, and the mute window
closes.  ``flush_final`` is the segment-finish counterpart: it puts
every block the builder still holds on the wire at the extent whose
observations are complete, and discards only per-instruction state
that no emitted range claims.  Its pieces:

* **A close landing mid-step** (between ``step_events``' promote and
  ``step_seal``, or at the top of a step before its promote — where the
  stall ceiling and the dead-latch sweep fire) holds a block that has
  just finished executing: its extent was measured and its tail destination snaps
  captured by that very dispatch's prologue.  It is emitted at that
  extent; the seal that would have resolved its terminating branch
  never ran, so the branch is declared unresolved
  (``CST_BB_FLAG_BRANCH_UNRESOLVED``, no branch-outcome records)
  rather than fabricated.
* **The pending-seal slot** emits at the last instruction whose
  observations are *complete*.  When a later dispatch measured the
  block (its prologue also captured the tail instruction's destination
  snaps), the stop is the measured extent.  When only the retired
  cursor answers (no later dispatch ran), the tail instruction retired
  but its snapshot was never taken — its successor never began — so
  the stop excludes it; the machine-shutdown close additionally
  excludes the instruction in flight at the close, which began and did
  not retire.  The **deferred** closes — the icount and simpoint
  budgets and the END marker — never reach this case: their slot holds
  the TB dispatching *now*, extent zero, so nothing is emitted, and the
  block each was armed on has already been emitted whole by that step's
  ordinary seal (step 6 above).
* **Fault-ledger entries** are forgotten: their prefixes are already
  on the wire, so a close loses only the pending continuations'
  identities, never instructions.
* **The sinks that remain** — the excluded tail's snaps, a
  mid-instruction's partial memops, retained events — are discarded as
  the honest complement of the stop rule: they are observations of
  instructions outside every emitted range.

The final entry a close emits for a context carries
``CST_BB_FLAG_THREAD_END``, and the user-instruction clock advances at
emission by exactly the published range, so what a segment bills
equals what it publishes at every close — an instruction the close
could not fully observe is outside the range, off the wire, and off
the clock alike.

A close does not always land on a block boundary.  The deferred ones
do — the icount and simpoint budgets and the END marker each wait for a
true-BB boundary — but a ceiling, a machine teardown or a guest death
stops execution wherever the guest happens to be, and those are the
closes this walk exists for.  The scoreboard's
``prev_start_pc`` resolves the last-executed *fragment* and says nothing
about how far into it the guest got, so the walk asks the
per-instruction architectural clock (``VCPUScoreBoard::insn_started``,
one JIT-inlined ``ADD`` per instruction, registered after every other
per-instruction callback so a pre-instruction reader sees only
*completed* instructions) how much of the in-flight TB actually ran, and
**truncates the block to the fully-observed extent**.  The truncated
block is
assembled by ``TemplateStore::commit_partial_bb`` into a store keyed by
``(asid_root, start_pc, n_insns)`` rather than into ``bb_map_``: the
complete-block cache is keyed by address alone and treats a shorter run
of the same bytes as an extent artifact, handing back the *longer*
committed template, which is exactly the over-claim the truncation
exists to prevent.  A chain that runs out with no terminating branch
goes the same way; when its extent turns out to match the complete block
already committed at that pc, that template is reused, so a trace where
nothing is really cut short mints nothing extra.

.. _unsealed-at-close:

How many blocks a close can leave unsealed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A true BB is sealed by its terminating branch.  A close that lands while
a thread is standing *inside* one has no branch to seal with, so the walk
finalizes the block at the extent that ran.  Two shapes reach that seal —
the close's measured extent cut a fragment part-way (``cut-mid-TB``), or
the walk consumed whole fragments and the chain was still open at a TB
boundary (``tb-edge``, a page-straddling block whose continuation never
came).  Both are reported per close, with the contributing
``(vCPU, thread)`` identities and the close route, in the exit summary's
*Unsealed true-BBs at a close* table.

The quantity is stated **per close**, and the reason it is not
``cut-short block templates minted`` is that that row counts distinct
*template shapes* inserted into the cut-short store, cumulatively, and
**seven** unrelated producers insert there: the two close-walk seals
above; the same walk run at a *departure* or a migration drain, where the
block is published at once and the guest runs on; the mid-run seal-walk
truncation and the mid-run cut where control left the block; the
extent-only mint (a block that *did* reach its branch, at a pc where the
complete-block cache already holds a different length); and the fault-cut
head prefix.  Each has its own row now, counted per *event* rather than
per distinct shape, so the events bound the shapes from above and a run
whose event rows sum to zero against a non-zero shape row has a producer
nobody named — which is how the departure producer was found (a two-thread
``-smp 2`` system cell minted one template with every other producer at
zero).

Two close regimes, and neither of them leaves work unsealed:

*Target-reached closes* — an icount or simpoint budget, and the SMP
peer flushes that ride with them.  These defer by a whole dispatch
(step 6 of the CP step above) precisely so the budget-crossing block
seals normally first, and the deferred close's own slot then holds a TB
that has not run.  Nothing is unsealed at such a close: measured 0 over
an ``-smp 2`` two-thread system cell and an ``-smp 4`` multi-process
churn cell, both closing ``OK`` at budget with ``clock_minus_wire=0``.

*Terminal closes* — the guest ending (user mode) and the END marker
(system mode).  The stopping instruction is *inside* a block on both
routes by construction, and both close that block out anyway, by two
different mechanisms:

* The exiting program's last block ends at its own **terminator**.  A
  ``syscall`` *is* a branch terminator, so ``mov $60, %rax; xor %rdi,
  %rdi; syscall`` and its per-ISA equivalents are architecturally
  complete the moment the syscall retires — there is no successor
  dispatch coming and none is needed.  ``close_seal_at_terminator``
  asks exactly that question (every instruction of the chain retired,
  last fragment ``TB_TERMINUS_COMPLETE``, the slot is this vCPU's
  current dispatch) and captures the terminator's own destination
  snaps, so the block is sealed with its register slice whole rather
  than cut one instruction short of the syscall that ended the program.
* The END marker's block ends at a **boundary the close waits for**.
  The marker fires from inside its own instruction's callback, so its
  block has begun and has not finished; the close is therefore deferred
  — ``marker_close_and_exit`` raises the arm, ``run_deferred_window_closes``
  takes it at the first step tail with no in-flight chain, which
  (because the arm went up *after* the marker's block began) is that
  block's own boundary, however many TBs it spans and whether it ends
  at a TB edge or a mid-TB branch.  By then the ordinary seal walk has
  emitted the block whole.

Measured **0** on every cell: user ``all`` and system ``all --system
--marker`` on x86_64, aarch64, riscv64 and mipsel, plus a two-thread
user cell.  On the four marker cells ``user insns actually executed``
equals ``user insns emitted to the wire`` (327, 378, 542, 547) with
``unpublished insns unbilled at the close`` 0 — billed is published,
and the block that made it so is the marker's own, on the wire entire.

The A/B against a synchronous END close is where the bound is legible.
Taking the same four marker cells with the close made synchronous
again, each publishes five instructions fewer (322, 373, 537, 542 —
the tail of the marker's own block), ``unsealed true-BBs sealed at a
close`` reads **1** on all four, and ``cut-short block templates
minted`` is one higher on each.  Billed still equals published there,
which is the point worth keeping: that identity holds on both sides
and so cannot be what decides between them — it says the close was
honest about what it kept, never that it should have kept less.  The
residue the deferral does not touch is aarch64's, whose cut-short
count falls 3 → 2 rather than to zero; the one it removes is the END
close's, and the remaining two are minted elsewhere in that boot.

So the bound is: **zero unsealed blocks at any close whose stopping
point is a block boundary or a block's own terminator, and one per
context only where a close stops a thread that has neither** — the
stall ceiling, a machine teardown, a guest death, where by
construction no boundary is coming.  A count above that is a defect,
not a corner: it means a thread was cut off at a stopping point the
tracer could have deferred past or sealed at.

The stop rule is also what keeps the final block's register deltas
complete.  A destination snapshot is captured one instruction late
(the *next* instruction's callback reads the registers the previous
one wrote), so an instruction whose successor never began has no
snapshot to give.  Stopping at the last fully-observed instruction
means every instruction inside the emitted range has its complete
memops and its complete post-execution register state — the range is
short of what retired by at most the one unobservable boundary
instruction, and it asserts nothing about it.

.. _end-defers-ruling:

The END marker defers: the ruling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Settled 2026-08-15.**  The maintainer's words: *"resolving the END
marker, we SHOULD delay closure until the end of the block once we see
it."*  It is recorded here, with its reason and its date, because this
section once left the policy open and a later reader took the silence
for a decision and reverted the behaviour to match the stale prose.

The reason is the one this whole section is built on — *blocks are
always closed out where it is in our power* — and at an END it is in
our power.  The marker's block is already executing when the arm goes
up, so waiting for its boundary costs no extra step and buys a sealed
terminal block carrying its memory operands, its register deltas and
its resolved terminating branch, exactly like every other entry.  A
trace whose final block is left unterminated for no architectural
reason is the defect; the deferral is what prevents it.

An END marker is a position as well as a stop, and the wire carries
both facts without collapsing one into the other.  The block is
published whole, and the marker's own index *inside* it is recoverable
from the template's instruction bytes — which is where a consumer reads
"the region of interest ends here" (:doc:`format` §4.2a).  Truncating
the entry at the marker would express that position by destroying the
block, and would discard the observations of instructions that
demonstrably ran; the format asks the consumer to read a published
position, not the writer to manufacture an unsealed block.

The deferral stops at the marker's own block and not one block later.
The arm takes at the FIRST boundary it survives to and deliberately
needs no second armed step — the budget close's second step exists
because its crossing TB has not run yet, and the marker's block has —
so nothing after the END marker's block reaches the wire.  ``range_cells``
``marker_end`` asserts all of it on the wire (whole sealed block, END
inside the published range, billed == published) and rejects the
truncated shape as its falsifier.

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
        push a :class:`WPBBEntry`, ``acc.clear()``, and start the
        next BB with the next fragment's ``start_pc``.  A single
        ``exec_tb`` can therefore commit multiple BBs (one per
        mid-TB branch the splitter found).
    f.  A speculative **memory** fault never reaches here: the
        load/store seam serves a deterministic placeholder value and
        returns, so the fragment runs to completion (``tb_ok`` stays
        true).  The memop drain marks ``bb_has_fault`` /
        ``bb_first_fault_idx`` at the placeholder-served instruction
        (first fault wins) and the excursion continues.  A **non-memory**
        synchronous fault (arithmetic / illegal-opcode, or a
        syscall-class kernel entry) still longjmps out of spec mode;
        ``wp_handle_fault_fragment`` marks that BB the same way, clears
        the pending exception, skips the faulting instruction and
        re-dispatches at its architectural fall-through, so the
        excursion runs on to the ``wpdepth`` budget.  When the faulting
        instruction is the BB's terminator the block is sealed there and
        the walk lands at the fall-through; mid-BB it runs the BB out to
        its natural branch first (avoiding a partial, template-polluting
        commit) and resumes the outer iteration from the skip PC.  The
        skipped instruction's destinations stay stale — the same
        deterministic placeholder the memory case uses — so its
        dependents still execute.  Faults on a ``BARE_BRANCH`` fragment
        do *not* force-commit (the delay slot is in a different TB and
        never landed) — they drop the in-flight accumulator and end, as
        does a fall-through that is an already-poisoned target or a PC
        that re-faults sixteen times.

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
  ``fault_insn_index`` at that instruction (``CST_BB_FLAG_SYNTHETIC_FAULT``
  with ``CST_FID_BB_FAULT_INSN`` on the wire), and the excursion
  **continues** on the placeholder to the
  depth budget.  Everything downstream of the marked instruction is
  synthetic; the **consumer contract** is that the marked instruction's
  result — and anything derived from it — is speculative filler that
  never architecturally retires.  This holds symmetrically in user and
  system mode, and covers loads and atomics; a wrong-path store to an
  absent page is sandboxed rather than faulting, exactly as a
  present-page speculative store is.  A **non-memory** synchronous
  fault (arithmetic / illegal-opcode) still longjmps out of spec mode;
  it is marked the same way, and the walk skips the faulting
  instruction and continues at its architectural fall-through, leaving
  that instruction's destinations stale as the deterministic
  placeholder its dependents read.
* **Syscall-class instruction.**  A syscall, software interrupt or
  unconditional trap (``syscall`` / ``int`` / ``svc`` / ``ecall`` /
  ``break``) is a control transfer whose taken side is a privilege
  escalation the single-address-space speculative model cannot follow.
  That makes the kernel edge *unfollowable*, not *terminal*: an
  out-of-order frontend fetches straight past a syscall and squashes it
  at retire, so the excursion takes the other side — the architectural
  fall-through — exactly as it takes the not-taken side of any other
  branch.  The block is sealed there (the terminator did end a block)
  and marked ``fault`` at the syscall, because the call itself is
  **never performed**: in ``*-linux-user`` the raise unwinds into the
  plugin's own landing pad rather than into the syscall dispatcher, and
  in system mode the one target that escalated inline (x86 ``SYSCALL``
  / ``SYSENTER``) unwinds the same way.  The syscall's result registers
  therefore hold the deterministic placeholder, and its dependents
  execute on it.  The exit summary's ``WP host syscalls blocked`` is
  the standing proof of the suppression and reads 0.
* **Translation unavailable, mid-chain.**  The *next* wrong-path
  target could not be fetched or translated — un-resident code under
  demand paging is the architectural case.  The last completed
  :class:`WPBBEntry` carries the ``translation_unavailable`` marker
  (``CST_BB_FLAG_TRANSLATION_UNAVAIL`` on the wire), making the
  honest fetch boundary distinguishable from a clean budget end.  A
  real frontend's fetch stalls at exactly that translation fault, so
  the consumer should treat the chain as complete-but-bounded, not
  defective.
* **Translation unavailable, first fetch.**  The excursion's *first*
  target cannot be fetched or translated, so the chain is empty and
  there is no :class:`WPBBEntry` to carry the marker; the condition
  rides the owning CP body entry itself as
  ``CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL``.  An empty or truncated
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
  chains look like early budget ends on the wire: no event names the
  bail, so a consumer separates them from chains that spent the whole
  budget only by summing the chain's instructions and comparing that
  against the ``wpdepth`` recorded in the header's ``command`` string.
  That comparison is what the visualizer reports as its ``stuck bail``
  class — an inference rather than a reading, and one a trace whose
  header records no ``wpdepth`` cannot make at all.
* **Flush re-run.**  A ``tb_flush`` that unwinds a spec-mode
  ``exec_tb`` before its guest instruction ran never reaches the
  wire: the walker signals the caller, which discards the truncated
  chain and re-runs the whole excursion in the fresh code cache.
  The wire contract is exact-or-longer — a flush-shortened chain
  would be indistinguishable from a silent bug.

.. _static-templates:

Static templates: opportunistic branch-alternate minting
----------------------------------------------------------

A consumer reconstructing a *trace-inferred* wrong path — replaying
mispredictions against the binary plus a BTB model, rather than replaying
the plugin's own WP excursions — needs decode coverage of code that is
fetched on a mispredicted path but never architecturally executed:
predicted-not-taken fall-throughs and BTB-miss wanders.  An executed-only
template dictionary cannot resolve those PCs.  ``static_templates=1``
closes the gap by minting the untaken side of every evaluated branch as
an ordinary, never-executed dictionary entry, in both user and system
mode — the mechanism needs no region enumeration, so the mode split
other approaches would force does not arise.

At every branch the correct path or a wrong-path excursion resolves, the
plugin checks whether the side NOT followed already has a template and,
on a miss, decodes that one true BB through the same
``qemu_plugin_cap_decode`` -> ``decode_detail_to_generic`` ->
fragment-splitter path the dynamic path uses, then mints it.  The
alternate is dictionary-only: no :class:`WPBBEntry`, no dynamic state,
no body record, and no wire flag at all — a minted alternate is
indistinguishable from any other block that simply never executed,
because that is exactly what it is.

Two hook sites cover the two gaps a wrong path alone leaves:

* **The wrong-path walk** (``wp_commit_bb``, part of the WP-walker's
  phase pipeline — see :ref:`wp-flow`).  A branch *inside* a
  wrong-path block resolves only the direction the excursion followed;
  its untaken side is never walked, so an executed-plus-wrong-path
  dictionary misses it.  ``altmint_conditional_alternate`` mints the
  untaken side once the block commits.
* **The correct-path seal** (``collect_finalized_bbs``, the
  PathBuilder's shared seal walk — see :ref:`cp-flow`).  When a sealed
  branch's wrong-path fork will not launch (``wpprune`` pruned it,
  ``wp=0``, or paging is off), nothing else decodes its untaken side,
  so the seal queues that PC and mints it (``altmint_pc``) once
  ``data_lock`` is released.  When the fork does launch, the wrong
  path itself covers the untaken block — and its own inner branches
  feed the first hook — so the seal leaves it alone.

From each freshly-minted alternate, ``static_depth=N`` (default 4)
recursively mints its statically-known successors — the architectural
fall-through always, and a direct branch's decoded target — as a DFS
worklist bounded by the existing-template dedup (``alt_or_bb_covered``)
and a per-segment mint budget (``CST_ALT_MINT_BUDGET``); an indirect
terminator ends the chain.  Alternates live in a segment-scoped
``alt_map_``, a sibling of ``bb_map_`` keyed by the same
``(asid_root, start_pc)``; at serialization an executed template always
shadows a minted alternate at the same key, so the trace body is
byte-identical whether or not the option is on — the delta is
templates-section-only.  Guest bytes are read with the same probing
``qemu_plugin_read_memory_vaddr`` the wrong path uses (mapped page ->
decode; unmapped -> skipped and counted), so minting never demand-pages
or perturbs the guest.  The exit-time summary reports the mechanism's
``checks`` / ``mints`` / ``depth_mints`` / ``skips_unmapped`` /
``budget_hits`` counters.

Opportunistic minting superseded an earlier eager executable-region
*sweep* (``qemu_plugin_walk_exec_regions`` plus a late-mapping growth
hook), which decoded a guest's entire mapped executable footprint up
front into a dedicated ``static_map_`` and carried a per-insn
``CST_INSN_FLAG_STATIC`` wire bit (bit 3, now back in the reserved
pool).  The sweep worked only in user mode and paid the decode cost for
a footprint most of which a consumer's fetch pattern never reached;
minting delivers the same coverage goal convergently, in both modes,
with no wire-format footprint.  See ``static_templates_plan.md`` for
the full design history.

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
host icount, and no guest-kernel modification.

That a run of bytes is a marker is a property of the **bytes**, so it
is decided in the bytes, at translation time: one ``memcmp`` over the
TB's delivered instruction stream against the START/END patterns, under
a single gate — not spec-mode.  Base QEMU's translator never ends a TB
inside a magic-sequence prefix (the never-split guarantee, see
:doc:`qemu_modifications`), so the three instructions always arrive
together in one TB and there is no unresolved-prefix case, no execution
callback, and no wrong-path fence beyond the one gate.  Two deliberate
semantics follow: detection fires at TRANSLATION (reach, not
execution), and a jump landing mid-sequence executes fewer than the
full run of magic instructions and is NOT a marker.

START latches the marker sequence's **virtual address**.  The window
*is* that vaddr; every address space that maps its bytes is traced —
concurrent instances, same-binary successors and fork children
included — and compiling the marker out is how a process opts out.
Identical ``(vaddr, bytes)`` is the same window by construction, so a
second instance at the same layout shares the first's window.  The
marker-sequence page must stay resident (``mlock(2)`` it before START):
an unreadable window vaddr at a gate refresh gates off, honestly and —
when the refreshing context is the one that was gated, i.e. the prior
per-vCPU gate bit is set and the live root still equals the carried
last-gated label — counted (``gated context lost marker page
residency``, a must-be-0 witness).  A foreign context that does not map
the window vaddr also reads as unreadable but is the content gate
working as designed; it is counted only as ``gate refresh evaluated
NOT traced``.

A latched window defines both the trace filter and the window clock:

* **User privilege in a gated address space** is the ground truth for
  "the workload's own instruction".  Those instructions are traced *and
  counted*: the window budget, the progress heartbeat, and the
  finish report all run on this user-instruction clock, so a
  marker-mode window covers the same user-space instructions a
  user-mode run of the workload would.

  The clock counts what **executed**.  It reads the per-instruction
  architectural slot (``VCPUScoreBoard::insn_started``), not the per-TB
  ``insn_count`` add fired at TB *entry* — that add credits a
  dispatched TB's whole instruction count before the TB has run, so a
  block the guest entered and did not finish was billed in full, and a
  block cut short by a fault was billed once in full and then again
  from its resume point.  The bill is lagged by one dispatch (the
  instructions observed at a dispatch are the ones the previous
  dispatch's TB executed) and the segment close folds the in-flight
  block's own executed prefix, so nothing is left uncounted at the
  end.  ``insn_count`` itself is unchanged: it is the BBV-identical
  positioning clock that SimPoint offsets are selected against, and it
  stays what it is.  The old TB-entry arithmetic is retained as an
  instrument — ``user_clock_billed_insns`` minus
  ``user_clock_retired_insns`` is the phantom bill, visible instead of
  silently gone.
* **Kernel execution in a gated address space** (syscalls, fault
  handlers — and, per the kernel-keep ruling, borrowed-mm kernel
  threads and post-switch tails running on the gated page tables) is
  traced but *not counted*.  Its templates carry
  ``is_system``, stamped from the live correct-path privilege at
  execution time — authoritative over any wrong-path seed, because
  speculation can cross the privilege boundary and translate code
  in the wrong context — and serialized on every instruction
  descriptor as the ``SYSTEM`` flag bit.
* **An address space that does not map the latched bytes** is neither
  traced nor counted.  The traced flow's own deferred prev is not lost
  with the span — it is emitted at the boundary, at its measured
  extent, with its terminating branch honestly unresolved (see
  :ref:`emit-at-departure <emit-at-departure>`); async excursions take
  the mute suspend instead — see :ref:`async-exclusion`.

A translation-bypassing privilege level (RISC-V M-mode firmware, which
``satp`` does not govern) commits no address-space write, so the gate
bit simply stands and firmware reached from a gated context is traced
with it (v4 default, maintainer-vetoable).

A workload shorter than its budget emits the **end marker** (the
same sequence shape, built on ``CST_MARKER_END_MAGIC``) just before
it exits.  Executed in the pinned address space, it closes the
window there — the "budget *or* program end" stop — at the end of
the true BB the marker fired inside, so that block reaches the wire
whole (:ref:`end-defers-ruling`).  An END releases every latched
vaddr the ending context maps (that set *is* "this process" under
content gating; two same-vaddr instances share one window, so the
first END un-gates both); the last window's release closes the
segment, and the finish line reports ``END`` rather than an
underrun.

Segment opens in marker mode follow the same per-thread boundary as
every other mode: ``reset_segment_local_state`` runs once on the
opening thread (global stores plus its own TLS), and every other
vCPU thread resets its own PathBuilder, async state, and event
queue as it observes the bumped segment generation on its next
step — TLS cursors can only be reset from their own thread.

A mid-run open executes on one vCPU but activates **every**
vCPU's scoreboard (``is_active`` mirror plus the budget sentinel,
each ``is_active`` write followed by ``refresh_ctx_gates`` to stamp
the derived ``trace_this_ctx`` gate): on an SMP
guest the pinned process's threads run wherever the scheduler put
them, and a vCPU left inactive would silently carry no trace
coverage — and no user-clock contribution — for the whole segment.  The user-instruction clock's delta source is likewise
per-vCPU (each vCPU's fold reads its own ``insn_count`` cursor;
``user_count_reset`` seats the opener's cursor exactly and marks
every other vCPU's unprimed, so its first fold contributes zero
rather than its pre-pin backlog).

A marker window is the only window a system-mode capture has:
``icount``, ``simpoint`` and ``symbol`` position a clock, and a clock
cannot say whose instructions it is counting, so they are refused at
startup under ``*-softmmu`` (see :doc:`quickstart`).  They remain
user-mode windows, where qemu-user emulates one program and the
question does not arise — and there the pin holds ``UNPINNED``, so
the whole machinery costs one relaxed atomic load per TB.

A SimPoint schedule is not an exception to that: it is a *second*
input, composed onto the marker window as
``marker:...+simpoints=<file>+interval=<n>``.  The marker latches the
address space and zeroes the process's user-instruction clock; the
offsets then position the capture on that clock, which is what makes
offsets derived from a user-mode BBV run valid here (kernel work is
traced and attributed by the excursion ownership rules, but never
advances the clock).  The anchor and the schedule stay separable —
neither turns the other on.

.. _fault-excursions:

Synchronous-fault excursions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Synchronous faults — page faults, TLB refills, lazy-enable traps —
are *kept*: the handler is real, workload-induced kernel code.  The
tracer's contract for them has two halves: handler code is emitted
first-class at its exception-nesting depth, and the faulting BB is
emitted in **split pieces, in program order** — its executed prefix
goes on the wire *at the fault*, ahead of the handler that
interrupted it, and its resumption is emitted after the excursion as
a *continuation* of the same template, each piece declaring the
executed range it is complete for (:doc:`format` §4.2a).  Nothing is
deferred, reassembled, or placed retrospectively.

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

On the plugin side, each drained ``FAULT_ENTER`` first takes the
aborted attempt back off the window clock (a pushed fault re-executes
its faulting instruction, so the started instructions at and past the
resume index will run — and be billed — again), then is classified
against the deferred prev (see :ref:`path-builder`).  Every emission
below is a *split-emission piece*: the range ``[lo, hi)`` of the
faulting BB's template, at the fault depth the block ran at, with the
terminating branch unresolved (the range never reaches it) and no
wrong path.  Whatever the range does not claim — the aborted
attempt's memops, the excluded tail's snaps — is dropped afterwards:
it is not an observation of a retired instruction, and the
re-execution delivers it again.

* **Case (a) — re-fault.**  The resume PC matches an in-flight
  ledger entry ``{resume_pc, asid}``: the same instruction faulted
  again (a TLB refill followed by the demand fault is *one* faulting
  instruction).  Nothing new retired, so nothing new is emitted; the
  entry is marked back in flight.  One refinement: a bulk-memory
  self-loop that re-faults having retired further *iterations*
  mid-piece publishes them as a one-instruction piece at the loop —
  real retirements are never held — with the continuation cursor
  staying on the instruction.
* **Case (a2) — second fault, same block.**  The resume PC is new,
  but the faulting TB is a byte-identical subrun of an in-flight
  entry's template and the new resume PC lies inside that template:
  a *later* instruction of the same pending block faulted (the
  archetype is a load's demand-zero fault followed by a store's CoW
  fault in one BB — the resume suffix re-executing after the first
  fault is a subrun of the entry's own template by construction).
  The suffix retired ``[cursor, k)`` before the new fault, and that
  mid-excursion continuation of the same template is emitted *now*;
  the entry's cursor and resume key advance to the new faulting
  instruction, so the eventual completion continues from the final
  suffix.  Minting a second ledger entry keyed at the first resume
  PC instead would leak the original entry.
* **Case (b) — new fault.**  The resume PC lies inside the deferred
  prev: prev *is* the faulting BB and its terminating branch never
  ran.  It is folded into a serializable template (force-committing
  an incomplete head if needed), its executed prefix ``[0, K)`` — up
  to the faulting instruction — is emitted at the fault, and a fresh
  ledger entry records the block's identity: the full template, the
  resume PC, the event-stamped address space, the owning thread, the
  depth the block ran at, and the emission cursor ``K``.  When the
  resume PC is not an instruction of the folded template (a
  force-committed incomplete head), no prefix can be named: nothing
  is emitted, no entry opens, and the accumulators drop with the
  unnameable block.
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

A ``FAULT_RETURN`` marks its ledger entry returnable, but the
continuation rides the resume suffix's *seal*, one or more steps
later: when a sealed BB starts at an entry's resume PC, the
**completion** emits the suffix as a continuation of the entry's
template — the *same* ``template_id``, ``bb_start`` at the entry's
cursor (the faulting instruction's index; the resume re-executes it),
the seal's resolved terminal branch and its wrong path — and erases
the entry.  Any leaked same-thread entry sitting *deeper* on the
ledger (strict LIFO says an inner excursion unwinds first, so a
survivor lost its own continuation) is simply retired with it: it
holds nothing emittable — its prefix reached the wire at its fault —
and retiring it keeps the depth count honest.  Completion is keyed on
the sealing context's ``(thread,
asid)``: the thread dimension is implicit (the PathBuilder is
per-vCPU-thread state), and the seal's effective pin asid is the
second half of the key.  A *user* entry completes only when its
event-stamped asid equals the seal's — which makes the same-VA
swallow (an entry from *another* address space, reachable through
ASID reuse since every process maps code at the same low VAs,
consuming an innocent block's seal) impossible by construction, so
the byte-content comparison on that arm is a diagnostic, not a
gate.  A *kernel-code* entry additionally completes on the
byte-content path when the asid key misses: a kernel fault's event
stamp is whatever mm is loaded at the fault instant — under
multi-process churn routinely another task's, for the same reason
kernel-excursion ownership exists — while the ledger only ever
holds the pinned process's own excursions, so content identity over
the one shared kernel image is the reliable key there.  A returned
entry is preferred by event identity; an entry whose return was
never observed (a non-LIFO guest return — a context switch inside a
blocking fault resuming the outer task first) completes on the same
keys at its suffix's seal.

**Return by diversion (exception-table fixup).**  A handler may end
an excursion without re-executing the faulting instruction: the
kernel's exception-table fixup *advances* the resume point past it
(Linux/MIPS ``handle_sys`` substitutes zero for an unreadable stack
argument and returns to the next load; ``copy_user`` error paths on
every ISA share the shape).  The exception return then targets the
fixup, not the pushed resume PC, so the pop's exact match rightly
refuses it and no ``FAULT_RETURN`` exists.  The dispatch that
re-enters the ledger entry's own template at an interior PC other
than the resume PC — arriving from *outside* the template, which is
what distinguishes it from a resumed suffix flowing across a TB
boundary — is the witness that the excursion is over: the entry is
retired on the spot (``census frames diverted``), its merge dead by
construction, because the resume PC was skipped and a later dispatch
there belongs to a different invocation.  The skipped instructions
never retired and never reach the wire; an already-published prefix
stays behind as an abandoned open invocation, which §4.2a licenses
exactly when the excursion is on the wire to explain the cut; and
the re-entered code runs as a fresh chain of its own template.
Leaving such an entry in flight instead would count a dead excursion
into every later stamp of the thread — the block's own resumed
pieces and the next fixup fault's handler would emit at the *same*
depth — and would let the next fault's advanced resume PC read as
mid-excursion retirement of instructions the fixup skipped.

.. _emit-at-departure:

**Emit-at-departure across a foreign or abandoned span.**  A
foreign-ASID dispatch (or an abandoned async window whose departure PC
was never learned) can preempt the pinned process while the
pending-seal slot still holds its previous block — including *exactly*
at a handler's return, where the departing block is an inner handler
level whose seal has not yet run.  The block executed; holding it for
a resume that may never come is a deferral the trace's program order
cannot absorb, and dropping it would lose an emitted level (a
``2 -> 0`` depth jump the ``syscall_fault_nesting`` oracle flags).  So
the block **departs the traced flow and is emitted at that moment**
(``emit_prev_at_departure``): at the extent measured by the first
dispatch after it — whose prologue also captured the tail
instruction's destination snaps, so every instruction in the range is
fully observed — at the depth it executed at, with its terminating
branch declared unresolved (``CST_BB_FLAG_BRANCH_UNRESOLVED``, no
branch-outcome records): the resolving successor is on the far side of
an excluded span, and the format forbids fabricating one.  Anything
past the measured extent was never observed and is dropped with the
departure.  An interrupted handler level therefore reaches the wire at
its own depth *before* the span, in program order — the wire steps
``2 -> 1 -> 0`` (or ``0 -> 1 -> 2`` on a re-nest) across the span
rather than losing the intermediate level.  The **abandoned-async**
arm emits the same way but falls through to promote the current TB
(kept — the pinned process at user privilege is real traced content):
that TB is the *other* guest thread the abandoned window hid, not the
departed block's successor, and emitting the departed block with its
branch unresolved is what avoids sealing it against the wrong thread
(the cross-thread taken edge the departure-PC seal exists to avoid).
A pending continuation whose resume suffix departs this way keeps its
ledger entry; if the continuation never seals, the entry is retired —
by the completion's leaked-deeper sweep or the segment close — losing
no instructions, since a ledger entry holds nothing emittable.  Off
the contention path — user mode and a deterministic single-process
system trace cross no foreign or abandoned boundary — no departure
fires and the output is byte-identical.

**The migration arrow (SMP).**  The pending-seal slot is per-vCPU, but
program order is per guest thread.  When the guest scheduler moves the
traced thread to another vCPU, the block the vacated builder still
holds precedes everything the thread will emit from its new vCPU — and
nothing on the old one is coming to seal it: a vacated vCPU idles
inside the excluded async window that delivered the migration, so the
foreign-boundary drain never fires there.  The holder is therefore
drained **at the owning thread's first promote on its new vCPU** — the
proof that its program order continues there — through the same
departure emission: measured extent (the stash, or the vacated vCPU's
parked retired cursor minus the never-snapped tail instruction),
executed depth, terminating branch declared unresolved, and the window
clock billed exactly what the drain publishes.  Left parked instead,
the block surfaces only at the segment close, thousands of entries out
of its context's program order — the source of the historical SMP
churn shapes: a CFG-impossible adjacency where the parked block's
neighbours sealed without it, two parked executions of one loop block
surfacing back to back in the close's flush, and a context-final flag
on an entry whose context continues.  ``CST_NO_MIGRATE_DRAIN``
restores the parked behaviour as a falsifier arm.  A thread that never
changes vCPU — every user-mode trace, every ``-smp 1`` system trace —
never takes the arrow and its output is byte-identical.

**Falsifier arms of the SMP rows.**  The SMP condition rows include
several that must read 0, and a row that has only ever been observed at
0 is equally consistent with a correct tracer and with a detector wired
to nothing.  Each therefore has an arm that makes it fire on demand, in
one of two kinds.  *Synthetic* arms exercise the predicate, the counter
and the report on the run's own data while leaving the wire
byte-identical: ``CST_SMP_DUP_FALSIFY`` replays one claim through the
duplicate ledger, and ``CST_SMP_STAMP_FALSIFY`` inverts the copy of the
close's emission prediction that the mispredict comparison reads —
never the copy that decides the ``THREAD_END`` stamp.  Their
wire-neutrality is measured rather than asserted, and measuring it takes
care: a user-mode trace is reproducible only when both arms share one
output path and an environment block of identical size (argv and environ
are on the guest stack, and the trace records it), and one register field
carrying a guest stack pointer varies between two runs of the *same* arm
and must be masked.  Under those controls the armed and unarmed traces
hash alike while the row moves.  *Severing* arms
genuinely remove the mechanism, because the row's whole meaning is that
something went unpublished and no synthetic fire could honestly stand
for it: ``CST_NO_MIGRATE_DRAIN`` parks the migrated holder again, and
``CST_SMP_DRAIN_UNK_FALSIFY`` forces one drain's extent lookup to fail,
so ``migrate drain extent unknown`` is proven reachable.  A severing arm
drops a block, and the validator's content checks are expected to refuse
the resulting trace — that refusal is the arm working.  None of these is
on by default and none is consulted by tracer logic.

The peer-slot extent **provenance** rows take synthetic arms for the
same reason and of the same kind.  At a close, a peer vCPU's held slot
is classified by which lookup can still answer for it: the stash the
first dispatch after the promote recorded (definitively past), the
vCPU's live retired cursor (a thread that may still be executing), and
whether the slot is that vCPU's current in-flight head — a block the
close is reading mid-flight.  Because the stash is written by that
first dispatch whether it was owned or foreign, a peer still holding a
slot at a close has almost always dispatched again since, and on
x86_64 and mipsel the two narrower rows had never been observed above
0 — 400 instrumented cells, 76 of them firing the stash row and none
firing either other.  That zero was an artefact of which ISAs had been
run, not a fact about the tracer.  Measured on a 160-cell aarch64 and
riscv64 system wave (``--smp 2`` and ``--smp 4``, no arm anywhere): of
98 peer-slot classifications, 77 came from the stash and **21 from the
live cursor**, spread over 21 cells, 11 aarch64 and 10 riscv64.

Every one of those 21 was also the in-flight head, and that identity is
structural rather than lucky: the stash is missing exactly when no
dispatch has followed the promote on that vCPU, and in that case the
held slot still *is* the vCPU's current dispatch.  The two rows
therefore name one window, from two sides.  What the arms —
``CST_SMP_PEER_LIVE_FALSIFY`` and ``CST_SMP_PEER_INFLIGHT_FALSIFY`` —
buy is reaching that window on demand, on any ISA, instead of by
scheduling draw.  They perturb only the copies the classification reads
and print the machine's real answer beside the forced one; the three
counters are written in exactly one place and read in exactly one (the
stats report), so no arm here can reach the wire at all.

Peers are **not** quiesced at a close: ``exec_lock`` serialises the
per-TB callbacks, and a peer executing translated guest code is in
none of them.  A slot classified as the in-flight head is therefore
read from a vCPU that may still be running, off an ``insn_started``
slot that vCPU's own inline adds are still advancing.

On the wire (``CST_FLAG_FAULT``, set in marker mode; user-mode traces
advertise no fault machinery): every CP entry carries ``fault_depth``
(0 = normal code, ≥1 = handler code at that nesting level,
baselined per segment).  User-privilege entries always stamp 0:
user code is never handler content, but a preemptible kernel can
context-switch inside a blocking fault handler and resume another
guest thread's user code while the interrupted task's frames are
still live on the vCPU's per-CPU fault stack — the clamp keeps
that depth from leaking onto the resumed thread (its *kernel* work
keeps the raw-baselined depth, an accepted approximation of the
per-vCPU stack).  A faulting BB appears as its split pieces, the
excursion's entries between them at their depth: each piece declares
the executed range it is complete for, and a consumer rejoins the
invocation from the ranges (:doc:`format` §4.2a).  Two environment
toggles support A/B diagnosis: ``CST_NO_FAULT`` (marker mode runs
without the fault feature) and ``CST_NO_FAULT_WP`` (a fault
continuation's emit carries no wrong-path chain).

.. _async-exclusion:

Asynchronous interrupts and the two handler-tracing flags
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two independent flags choose whether each kind of handler excursion is
traced.  ``faults=1`` (default) traces synchronous-fault handlers at
their nesting depth, the interrupted block emitting in split pieces
around them (:ref:`fault-excursions`); ``interrupts=0`` (default)
excludes asynchronous
handlers whole.  Setting ``faults=0`` excludes the synchronous handler
instead, and ``interrupts=1`` traces the asynchronous handler instead —
each reusing the other's mechanism, because the two are mirror images:
one suspends capture across the excursion, the other captures it at a
depth.  Both are system-mode concepts; in ``*-linux-user`` neither flag
has any effect.

Asynchronous interrupts — timer ticks, device IRQs, the scheduler
activity they trigger — are not induced by the traced workload, so by
default the entire delivery-to-return excursion is excluded from the
trace.

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
segment's first prime), that seal target is unavailable, so the
deferred prev is emitted at that moment instead, at its measured
extent with its terminating branch unresolved (see
:ref:`emit-at-departure <emit-at-departure>`) — the current
(other-thread) TB then promotes fresh, taking no seal from a block
that was never its predecessor.

**Tracing the asynchronous handler (``interrupts=1``).**  When the
handler is worth tracing — asynchronous kernel work is real
OS-overhead a full-system model wants — the capture is inverted rather
than muted.  The window contributes one exception-depth level, added to
any live synchronous-fault nesting, so the handler's kernel blocks
appear at depth ``>= 1`` between the interrupted context's entries; the
same kernel-excursion ownership that attributes a synchronous handler
attributes this one, keyed to the address space the interrupt was
delivered from.  No split is needed — an asynchronous interrupt is taken
at a basic-block boundary, so the interrupted block is complete and no
range divides — but the
seal must still target the **departure PC** (the same substitution the
abandoned-window recovery makes), because the block executing after the
interrupted one is the handler entry, not its architectural successor.
The window closes on ``ASYNC_RETURN`` (or the abandoned-window recovery
at a pinned user TB, which proves depth 0); the resume TB re-executing
the departure PC then seals normally.  The depth rides the existing
fault trailer, so a captured async handler needs no new wire records.

**The window's lifetime and the level's ownership are different
questions,** and the tracer answers them separately.  The *lifetime* is a
per-vCPU fact owned by QEMU: one flag, raised at the outermost delivery
and lowered when the departure PC is re-executed.  The *level* is a per
guest-thread fact, because ``fault_depth`` is the nesting the emitting
block executed at and that nesting belongs to the block's own
``thread_id`` (:doc:`format` §4.2a) — so the level belongs to the context
the interrupt was *delivered in*, and to no other.  The tracer therefore
records that context's thread at the ``ASYNC_ENTER``, and every read of
the level is a predicate against the executing block's thread: present for
the owner, absent for a peer.  That is the same rule the synchronous side
applies to its frames (a frame counts only for the thread that entered
it), and it has the same shape — a level goes **dormant** while a peer
thread is scheduled onto the vCPU and becomes **live again** when its
owner is rescheduled, for as long as the window is open.  A context change
is not evidence that a handler finished, so it destroys nothing; only the
window closing is.

Keying the release on the *address space* instead would be both wrong and
insufficient.  Wrong, because an address space that leaves the capture
context routinely returns to it before the window closes, and a rule that
fires on the departure cannot un-fire on the return.  Insufficient,
because a switch between two threads of one process, a kernel thread on a
borrowed mm, and a switch between two live processes holding the same
recycled narrow ASID are all context changes that commit no
address-space-write event at all; the per-thread predicate covers them
without needing any event.

The abandoned-window recovery splits along the same seam.  A pinned user
TB proves the *vCPU* is not inside an async handler — user privilege means
every exception level has been returned from — so QEMU's flag is lowered
there unconditionally; leaving it raised would suppress every later
capture on that vCPU, because each producer is edge-gated on the flag.  It
proves only that *this thread* is at async-nesting depth 0, so the level is
released only when the thread reaching user is the level's owner,
mirroring the stale-frame sweep that spares a peer thread's frames.  When
the delivering thread's identity was never sighted the level is
unattributable, stays dormant everywhere, and is released at the first
opportunity rather than held.

The ``async capture windows …`` counters report the ledger: windows
opened, how each one closed, how many depth stamps each served for its
owner versus for a peer, and how many of the windows that served a peer
stamp saw no address-space write at all — the last being the measure of
how much of the condition an address-space rule cannot see.

**Excluding the synchronous handler (``faults=0``).**  The mirror case
reuses the async mute.  While a synchronous-fault excursion is in
flight the handler's capture is suspended and its basic blocks are
dropped at the seal, exactly as an excluded async window's are — but
the interrupted block still emits its split pieces: the executed
prefix at the fault, the continuation at the resume suffix's seal,
with nothing between them and depth ``0`` throughout (a nested
handler's own faulting block is handler content and is excluded with
the handler).  A ``faults=0`` trace therefore advertises
``CST_FLAG_FAULT`` yet never carries a depth ``> 0`` entry
(:doc:`format` §4.2a).

.. _time-transparency:

Guest-time transparency
-----------------------

Plugin work runs on the vCPU thread but is not guest execution, so
its host wall-clock cost must never be charged to guest time.  The
stakes are highest in system mode: instrumented cost billed to the
guest would put a timer-tick handler's cost against the tick period
itself, and a handler that outran its own period would leave the next
tick already pending on return.  Three cooperating layers keep the
guest's clocks clean; all are no-ops in user mode, and the QEMU side of
each is catalogued in :doc:`qemu_modifications`.

**That failure mode is the counterfactual, not a live hazard.**  With
the three layers in place no instrumentation cost reaches a guest clock,
so no amount of tracer work — however deep the speculation, however long
a single excursion — can produce it.  It is written down because it is
what the layers below are *for*, and because it is the thing an
unfrozen clock would cause.  It is not an explanation available for a
guest that stops making progress under a build that has these layers: a
frozen clock cannot be starved by host time, so such a case is a state
defect on the wrong path's restore, not a cost effect.

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
  teardown/re-entry cannot leak ticks.  The freeze covers both
  sources of guest time: the host wall clock (``cpu_disable_ticks``)
  and, under ``-icount``, the instruction counter, whose position is
  checkpointed at excursion entry and restored at exit.  A wrong-path
  excursion therefore consumes exactly zero guest time under either
  timekeeping mode, and the guest observes the same tick count with
  wrong-path simulation on as with it off.
* **Freeze-and-resync on exit.**  Freezing is only half the
  contract.  While the clock stands still the excursion rolls
  architectural state back, and the machine around the vCPU does
  not roll back with it: compare registers rewind underneath host
  timers that stay armed for the speculative deadline, interrupt
  lines keep levels their pending registers no longer agree with,
  and an interrupt controller that asserted a line mid-excursion has
  its assertion erased by the register restore.  QEMU's
  ``TCGCPUOps::spec_clock_resync`` hook closes all of that, per
  target, on every excursion exit.  Its contract is one sentence:
  *on return, every architectural clock or counter the guest can
  observe, and every armed host timer backing one, is consistent with
  the frozen virtual time* — as if the excursion had consumed exactly
  zero guest time.  The frozen clock is authoritative; an
  implementation resynchronises the sources to it, never the reverse.

  Each target reconciles all of its clocks unconditionally, whether
  or not that particular excursion is known to have disturbed one.
  The reconciles are idempotent, so the only cost is the recompute,
  and correctness does not depend on having enumerated every way a
  clock can drift.  What each target owns:

  .. list-table::
     :header-rows: 1
     :widths: 12 44 44

     * - Target
       - Counters
       - Timers and lines reconciled
     * - x86
       - TSC re-pinned to the virtual clock at every thaw (it free-runs
         off the host rdtsc, a different oscillator from the one the
         virtual clock uses, so it drifts across every freeze).
       - LAPIC/TSC-deadline/HPET/PIT are armed directly off
         ``QEMU_CLOCK_VIRTUAL`` and hold no architectural shadow, so
         they need no re-arm.
     * - Arm
       - CNTVCT/CNTPCT are computed from the virtual clock; nothing to
         re-derive.
       - Every generic timer re-armed from its restored ``ctl``/``cval``
         (and CNTVOFF); the six inbound interrupt lines re-driven from
         ``irq_line_state``, which the excursion carries across the
         rollback as the device state it is.
     * - RISC-V
       - ``time`` is the ACLINT counter, a function of the virtual clock.
       - ACLINT machine timer and the Sstc ``stimer``/``vstimer``
         re-armed from ``mtimecmp``/``stimecmp``/``vstimecmp``, deferred
         expiries re-delivered; ``mip`` external assertions replayed over
         the rollback and ``CPU_INTERRUPT_HARD`` re-derived from it.
     * - MIPS
       - CP0 ``Count`` is a function of the virtual clock.
       - R4K timer re-armed from ``Compare``, a suppressed expiry
         re-delivered, and ``CPU_INTERRUPT_HARD`` re-derived from
         ``CP0_Cause.IP``.

  A target that does not register the hook accumulates clock skew
  across excursions; registering it is how a system-mode target opts
  in to wrong-path execution being time-transparent.

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
time, before a divergent fragment can ever reach commit, and the
revision seam handles the first by minting a new template of the new
shape (see :ref:`the discriminator <smc-discriminator>`).

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
  differ is disambiguated by path.  On a *spec-mode* translation it is
  treated as foreign / mid-refill content (a virtual address reused by
  another address space, or a page being demand-paged) and the read
  stays non-mutating.  On the *correct path* it is ground truth: the
  CPU really is executing these bytes.  In system mode a stable VA
  legitimately reads different bytes across CP translations (demand
  paging, ASID reuse), so the memo is refreshed rather than treated as
  a fault; and where the change is genuine correct-path
  self-modification, the revision-minting seam at true-BB commit turns
  it into a new template revision (see :ref:`smc-revisions`).

The **Capstone decode failure** signal poisons the TB's ``start_pc``
(adding it to ``g_poisoned_pcs``); the fragment is *not* created and
no exec-cb ``udata`` is registered for the TB.  Subsequent WP walks
check ``cst_pc_is_poisoned`` at the top of each iteration (excursion
entry excepted — see :ref:`wp-flow`) and abort before re-translating
the address.  This is what keeps a wrong path that wanders into stack
/ heap / data — bytes that do not decode — from minting garbage
fragments; it fires silently because that symptom is normal
speculative behaviour the tracer simply declines to record.

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

.. _smc-revisions:

Self-modifying code: template revisions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The true-BB cache keys on ``(asid_root, start_pc)`` and holds one
*live* template per slot.  When a correct-path re-execution finalises
a block whose live template holds different code, the commit seam
(``TemplateStore::resolve_true_bb``) mints a **revision**: it builds a
fresh template with a new ``template_id``, retires the previous live
template into a segment-scoped stash (still serialised, because body
entries emitted while it was live reference it), and installs the new
one as live.  Body entries always name the ``template_id`` live when
they executed, so the revision timeline is implicit in the body's own
references — no new wire record, and ``CST_MAGIC`` is untouched.

.. _smc-discriminator:

**The discriminator** (``cst_classify_bb_match``, in
``champsim_tracer_smc_match.h``) reads the **overlapping prefix**: the
first ``min(committed, incoming)`` instructions, compared at PC-aligned
positions.  It answers one of three ways.

*EXACT* — same instruction sequence, byte-identical.  The committed
template is reused; this is the overwhelmingly common case.

*SMC* — an overlapping instruction's size or byte image differs.  The
code really changed, so a revision mints.  This test is **shape-
agnostic**: it does not care whether the rewrite preserved the block's
instruction boundaries (an in-place immediate or opcode patch), moved
them (kernel alternatives and static-key patching, JIT re-emission), or
changed the instruction count outright.  A revision is only a new
``template_id``, which the wire represents identically for any shape, so
the block's new layout constrains nothing.  A template's byte image is a
zero-padded fixed-stride copy of each instruction's real bytes, so an
instruction whose *length* changed can never compare equal to the one
previously recorded at its PC: the prefix walk sees a boundary move at
the instruction where it begins, however the boundaries downstream land.

*EXTENT_ONLY* — every overlapping instruction agrees byte for byte and
only the block's extent differs.  The same code was assembled over a
different run of itself: a chain sealed at a different terminator, a
page-split fragment, a chain force-committed by the fault machinery.
That is an assembly artifact, not a code change, so nothing mints; the
committed template is kept, a once-per-run explanatory note goes to
stderr, and the event is counted in ``smc_extent_artifacts``.  The
instructions of a true BB are contiguous, so ``insn_pcs[i]`` follows
from ``insn_pcs[i-1] + insn_sizes[i-1]``: a PC divergence *past* a
byte-identical prefix can only be an extent artifact.  Position 0 is the
exception — both arrays anchor at ``start_pc``, so a re-anchored start
is decided by the bytes at that shared PC.

Three properties bound the mechanism:

* **Lazy.**  A revision mints only when a mutated block *re-executes*.
  Writes to never-re-translated code never surface, so a JIT region
  written many times and entered once produces exactly one template.
* **Content-signature reuse.**  Retired revisions are indexed by an
  FNV signature of their byte image, so a mutation returning to a
  previously-seen state reuses that state's original ``template_id``.
  A/B/A/B call-target patching resolves to two ids, not four.
* **CP-confirmed only.**  Revisions mint only from correct-path
  translations superseding a correct-path-confirmed state — a
  wrong-path spec translation observing mid-write bytes never versions
  a template (the same guard the byte-change memo above applies).

A per-PC cap (``smc_revisions=N``, default 1024) is a backstop bug
detector: beyond N distinct states minting stops, the body keeps
referencing the last revision, and a loud once-per-segment warning
plus the ``smc_overflow_events`` / ``smc_overflow_pcs`` statistics
flag the anomaly.

*Instructions with an unbounded memory fan-out are fanned out into a
self-loop.*  An x86 ``REP MOVS`` executes N times against architectural
memory; an AArch64 FEAT_MOPS ``CPYM`` moves a register-sized span in
one execution.  Neither has any fan-out bound the wire could size a
slot table against, so instead of issuing hundreds of thousands of
memops on one entry the tracer surfaces each iteration as its own
``BODY_TAG_ENTRY``: iter 1 stays on the BB that *enters* the loop
(terminating that BB at the instruction's PC), and iters 2..N each emit
a fresh body entry on a 1-insn self-loop BB whose start_pc ==
fall_through_pc == that instruction's own PC.  See the *"Bulk-memory
self-loop BBs"* subsection of *Part II §5.2 "Memory Counts and
Addresses"* of the wire-format spec for the encoding details.
The self-loop BB's terminating insn carries
``branch_type = BRANCH_REP`` to alert consumers that the BB is a
synthetic 1-insn self-loop rather than an ordinary direct conditional
branch.

The fan-out UNIT is per family, because only x86 has an architectural
iteration to count: one element for a REP string op (1 load + 1 store
on REP MOVS, 1 store on REP STOS), one memory ACCESS for a MOPS bulk
copy/set, whose step size is a property of the implementation and whose
loads and stores arrive in per-step runs rather than in pairs.  Either
way each iteration's memops attach to that iteration's own body entry,
so the slotted families ``CST_FID_LOAD_ADDR*`` /
``CST_FID_STORE_ADDR*`` stay at the low end of their 0..511 range
however much memory the instruction moves, and the writer-side clamp is
left as a backstop that nothing currently reaches.

The splitter is what makes this work at the BB layer: neither QEMU's
x86 nor its AArch64 translator ends a TB at these instructions, so the
fragment splitter cuts the TB at each one.  A glibc ``memcpy`` on a
FEAT_MOPS guest is a prologue/main/epilogue triple in a single TB and
becomes three consecutive entries, all of whose memops arrive in one
buffer — which is why the recorder's straggler carry is bounded by
emission progress rather than by a fixed number of drains (see
``drain_cp_into_dyn_params``).

``MemAccessRecorder::record`` caps per-instruction memops at
``CST_FID_SLOT_COUNT`` = 512 on the WRONG path and drops the rest —
there is no overflow vector — which bounds the WP simulator's spec
mode, where ``REP`` can iterate arbitrarily many times against a
sandboxed memory.  (MOPS needs a second bound there: it runs its whole
transfer inside one TCG helper, so the plugin never regains control to
stop it, and ``mops_spec_clamp`` in ``target/arm/tcg/helper-a64.c``
truncates the spec-mode transfer size instead.)  The matching
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

The third mechanism has a measured limit, and it is the one place
the invariant can fail.  The deferral is paid for out of a finite
reserve; a wrong-path walk whose translation footprint exceeds it is
cut short at a depth set by host buffer occupancy rather than by
anything architectural, so the same guest run traced twice can
produce different wrong-path chains.  That is counted, not assumed:
the trace is flush-invariant only while ``WP chain cut by
code-buffer`` reads zero, which is why the tracer publishes it as a
must-be-0 row rather than describing the property as unconditional
(see :doc:`qemu_modifications`).

*Segment-generation stale-fragment guard.*  Switching segments
calls ``clear_bb_map()``, which drops the owning ``unique_ptr`` s
so any ``BBTemplate*`` held in another vCPU's in-flight chain
dangles.  ``reset_segment_local_state`` bumps a monotonic
``g_segment_generation``; every chain stamps the generation on each
``append_fragment`` and self-resets on mismatch, so the opening vCPU
can reset segment-local state without reaching into the other
vCPUs' chains.  Each vCPU's PathBuilder likewise resets its own
frames and pending-seal slot via ``on_segment_open`` as it observes
the bumped generation, and cross-segment references held by
persistent templates are ``SegRef`` handles that read as null once
stale.

*Per-vCPU stream state is keyed by* ``cpu_index``, *not by host
thread.*  The chain assembler, the PathBuilder, the CP memop
accumulator, the pending dst-register snaps and the deferred
window-close arms all live in clamped per-vCPU array accessors (the
``g_rep_state`` pattern).  Under MTTCG a vCPU and its host thread
coincide, but under round-robin TCG (``-accel tcg,thread=single``,
and therefore under ``-icount``) one host thread runs every vCPU,
and thread-keyed state would fold the vCPUs' interleaved streams
together at each scheduler slice.  The only per-vCPU values still
in ``thread_local`` storage are those whose whole lifetime sits
inside a single ``exec_lock``'d CP step (``g_wp_state``,
``g_capture_mute``, the emit-time transfer registers), which no
vCPU switch can interleave under either threading model.

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
