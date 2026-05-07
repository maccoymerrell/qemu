Architecture
============

This page describes how ChampSim Tracer is organized, the two main flow
loops (CP and WP), and the caveats every prospective modifier needs
to know.

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
   * - ``champsim_tracer_mnemonics.h``,
       ``champsim_tracer_mnemonic_tables.c``
     - Static tables: per-ISA insn classification (generic opcode,
       branch type, sync hint), per-ISA register classification, and
       per-ISA architectural properties (delay slots, etc.).
   * - ``champsim_tracer_generic_ids.h``
     - The portable enum domains:
       ``GenericOpcode``, ``BranchType``, ``SyncEventType``,
       ``GenericRegId``.  Everything in the plugin and the decoder
       agrees on these IDs.
   * - ``champsim_tracer_bb_template_cache.{h,cc}``
     - Two ``unordered_map`` caches.  ``tb_map_`` keyed by TB start_pc
       holds the per-fragment templates QEMU hands us; ``bb_map_``
       keyed by branch-target start_pc holds the *true* basic-block
       templates assembled from contiguous TBs.  Per
       :doc:`reference`, ``bb_map_`` is the templates section of the
       trace.
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
     - Captures source-register values on instructions whose templates
       say register data is needed.  Either inline at exec time (CP)
       or out-of-band against a wide pre-fragment regfile dump (WP).
   * - ``champsim_tracer_wp.cc``
     - The wrong-path simulator.  Saves CPU state, enters spec mode at
       a wrong target, runs ``cpu_plugin_exec_tb`` until depth budget
       or natural branch end, restores state.  See :ref:`wp-flow`.
   * - ``champsim_tracer_output.cc``
     - Wire-format encoder.  Owns the BitWriter, the v1.9 unified
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

1.  Bump ``insn_count`` by ``n_insns`` of the TB.
2.  Window check.  If we're outside an open segment but the icount has
    crossed the next configured window, open a new segment via
    ``start_trace_segment``.  If we're past the segment's stop, close
    it and (for SimPoint mode) advance to the next window.
3.  Read the previous TB's start, last-pc, fall-through, and
    "ends-in-branch" out of the per-vCPU scoreboard.  Those fields
    are populated by inline stores ``vcpu_tb_trans`` registered on
    *this* TB's first instruction, encoding *this* TB's
    parameters.  When the TB executes, the inline store fires
    early enough that by the time ``vcpu_tb_exec`` runs the
    scoreboard already describes the TB whose vcpu_tb_exec just
    fired — which from the chain assembler's point of view *is*
    the previous TB relative to the next one.
4.  Branch-transition observation: bump
    ``branches_observed`` / ``branches_taken`` / ``branches_not_taken``
    on the previous branch, and update its
    :class:`BranchHistory` record so the WP simulator has indirect
    targets to pick from later.
5.  Append the previous TB's template to the in-flight CP chain.
    The :class:`BBChainAssembler` glues consecutive fragments together
    until a TB ending in a branch completes a true basic block.
6.  Per-instruction attribution.  Walk the previous TB's
    ``insn_fields`` and bump the per-CP opcode / branch-type / src-reg
    / dst-reg counters in ``g_stats``.  Mirror the bumps into the
    histogram bucket if one is active.
7.  If the previous TB ended in a branch, finalize the chain into a
    true-BB template.  Resolve the wrong-path target (fall-through for
    a taken direct branch, the static target for a not-taken direct
    branch, the most-frequent-non-CP indirect target for an indirect
    branch).  Then either invoke the WP simulator or skip it.
8.  Build a :class:`BodyEntry` from the just-finalized BB plus the
    drained per-thread memop / reg-snap accumulators, and stream it
    through the writer.

Steps 4-7 happen under ``data_lock``; the BB cache writes plus chain
state are mutated there.  The actual write to the body stream (step 8)
holds only ``exec_lock`` — the writer is internally synchronized.

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

    a.  Look up the cached TB template at ``pre_pc``.  If absent, the
        template will exist after exec_tb has translated it.
    b.  Capture pre-fragment register values into a per-fragment wide
        snapshot if reg-data is enabled.
    c.  ``cpu_plugin_exec_tb()`` runs the TB.  Its memory callbacks
        fire and append to ``g_wp_state.mem_accesses``.  Other plugin
        callbacks (insn-exec, inline stores, vcpu_tb_exec) are
        suppressed by ``CF_MEMI_ONLY`` so the scoreboard stays clean.
    d.  Determine ``n_executed_in_tmpl``.  If exec_tb succeeded, the
        whole template ran; on a fault, find the faulting PC in
        ``tmpl->insn_pcs`` and cap there.
    e.  Append the executed-prefix's insns to ``bb_pcs`` /
        ``bb_fields`` / ``bb_bytes`` / ``bb_sizes`` and the matching
        bumps to per-WP attribution counters and the histogram bucket.
    f.  Attribute the just-captured memops to insn indexes by walking
        the executed prefix.
    g.  If the TB faulted on a non-branch insn, mark
        ``bb_has_fault`` / ``bb_first_fault_idx`` (first fault wins),
        poison the faulting PC against re-faults, set the next PC to
        ``fault_pc + last_insn_size``, and continue the loop into the
        same BB.
    h.  If the TB ended in a branch (ordinary completion *or* a
        syscall-style faulting branch), commit the accumulator to the
        BB cache via ``commit_true_bb``.  Push a
        :class:`WPBBEntry` carrying ``bb_has_fault`` /
        ``bb_first_fault_idx`` and ``clear_accum``.  If the post-PC
        is poisoned, end the chain.

3.  ``qemu_plugin_spec_mode_end`` + ``qemu_plugin_cpu_state_restore``
    +  scoreboard restore.

The chain returned to the caller is *moved* into the
:class:`BodyEntry`'s ``wp_entries`` field and serialized inline within
the same body record as its CP entry.

.. _caveats:

Caveats
-------

These are the places where reading the source would not be enough,
because the answer is "we deliberately do this and here's why":

*BBs always end in a branch.*  Per :doc:`/format`, ``bb_map_`` only
holds true basic blocks: the run from a branch target up to the next
branch.  The WP simulator now traces *past* in-flight faults precisely
to preserve this invariant — see step 2g above.  Earlier revisions
committed truncated faulted BBs and triggered "differing insn
sequence" warnings on the next CP commit at the same start_pc; if you
ever re-introduce mid-stream commits, the warning in
``commit_true_bb`` will scream.

*PC-deduplicated x86 string instructions.*  An x86 ``REP MOVS``
produces N memops at the same ``insn_pc``.  The wire format itself
handles arbitrary N — slots 0..15 use the ``CST_FID_LOAD_ADDR*`` /
``CST_FID_STORE_ADDR*`` slotted families and slots 16+ overflow into
the ``CST_FID_EXTRA_LOAD_ADDR`` / ``CST_FID_EXTRA_STORE_ADDR`` raw
vectors — so the CP path captures every memop a ``REP`` issues
regardless of count.  The WP path is more restrictive:
``MemAccessRecorder::record`` caps WP-side memops at
``CST_FID_SLOT_COUNT == 16`` per instruction and silently drops
the rest, because the WP simulator's spec mode can iterate
``REP`` arbitrarily many times against a sandboxed memory.  The
matching forward-progress guard inside the WP loop catches the
related case where spec-mode ``REP`` returns from ``exec_tb``
without advancing PC and would otherwise spin forever.

*atexit ordering inversion.*  QEMU registers its plugin atexit
callback *before* the plugin shared object's own ``__cxa_atexit``
destructors run.  By the time ``plugin_exit`` fires, the C++
containers in ``g_bb_template_cache`` and ``g_branch_history`` have
already been destroyed and their ``size()`` returns 0.  We mirror the
relevant cardinality counts as raw ``uint64_t`` in ``g_stats``
(``tb_templates_created`` etc.) and bump them at insertion time so the
exit-time summary still reports useful numbers.

*Thread-locals at exit.*  The CP memop accumulator is a TLS vector.
On REP-heavy workloads it can be MiB-sized and backed by a direct
``mmap``.  Forcing ``shrink_to_fit`` from atexit was observed to
SIGSEGV deep in ``__libc_free`` because some glibc heap state has
already been torn down.  ``cleanup_current_thread`` therefore only
``clear()`` s; the TLS destructor runs the natural vector destructor
afterwards.

*GMutex, not std::mutex.*  ``<mutex>``'s transitive include chain
pulls ``<cctype>``, which goes through QEMU's ``include/qemu/ctype.h``
shadow that breaks libstdc++'s ``using ::isalnum;`` declarations.  We
keep ``GMutex`` everywhere to avoid the build-time hazard.

*Register IDs are 8-bit.*  ``GenericRegId`` reserves the full
0..254 range and 255 is the count sentinel.  If your ISA needs more
than 256 distinct architectural registers, the wire format changes —
not just an added enum value.

*WP overlay persists across chains in v1.9.*  Earlier revisions reset
WP's delta-encoding state at every chain boundary; v1.9 keeps the WP
overlay across chains so hot speculatively-touched templates pay
first-observation cost only once per trace.  The decoder branches on
the magic byte to distinguish v1.8 (per-chain reset) from v1.9
(persistent).  Don't change it without bumping the magic.

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
``shift_type`` / ``shift_amount`` (AArch64) fields the plugin added
to ``qemu_plugin_operand`` — see :doc:`extending`.  WP-side capture
is suppressed by ``CF_MEMI_ONLY``; that's intentional, because the
suppressed insns generate no architectural memops to begin with.

*The CP chain's first fragment uses cached template data.*  When a
TB at start_pc=X is translated more than once (different cflags, page
flush + retranslate, etc.), QEMU keys its TB cache by ``(pc, cs_base,
flags, cflags)`` so distinct translations get distinct ``vcpu_tb_trans``
calls — but our BB cache keys by start_pc only and the *first*
translation wins.  This is fine in practice because the *insns at
those PCs* don't change (no SMC); whether the TB extends 5 or 8 insns
before the boundary doesn't change which PCs are part of the BB,
because the BB is bounded by the next branch.

*Stats are racy and approximate.*  ``g_stats`` increments are not
atomic; histogram-bucket increments are not atomic.  We trade
correctness-in-the-large for throughput.  Treat the printed numbers
as engineering-grade, not audit-grade.

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
     - Mutates the BB caches (``tb_map_``, ``bb_map_``), the chain
       assembler's fragment list, and ``g_branch_history``.  Acquired
       briefly inside the larger ``exec_lock`` window.
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
