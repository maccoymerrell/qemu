Validator (champsim_tracer_validator)
=====================================

``champsim_tracer_validator`` is the in-tree test harness for the
plugin.  It generates self-checking workloads, runs them under
qemu-user with the plugin loaded, then verifies the resulting ``.cst``
trace against the expected behaviour the generator already recorded.
It is the primary mechanism for catching tracer regressions before
they ship.

Layout::

  contrib/plugins/champsim_tracer/validator/
    ├── champsim_tracer_validator/      # the Python package
    │   ├── __main__.py            # CLI entry point
    │   ├── generator.py           # diamond-CFG / probe-coverage emitter
    │   ├── analyzer.py            # ELF post-processor (PC spans, helper leaf)
    │   ├── asm_blocks.py          # CodeBlock library + _register_probe
    │   ├── _probe_specs.py        # inline-asm coverage probes
    │   ├── _thread_test_asm.py    # hand-written 2-thread programs
    │   ├── validator.py           # the named checks
    │   ├── classify.py            # per-ISA reg classification scanning
    │   ├── _cst_decode_runner.py  # parses cst_decode's legacy output
    │   ├── _diff_entries.py       # entry-level diff helper
    │   ├── _system.py             # qemu-system-<isa> runner (marker/initramfs staging)
    │   ├── _multiproc.py          # multi-process ASID / marker-latch harnesses
    │   ├── _smc.py                # self-modifying-code workload family (shape-preserving + shape-changing) + discriminator truth table
    │   ├── _full.py               # `full` unified runner: tiers + coverage registry
    │   ├── _mutation.py           # `mutation` adversarial strictness harness
    │   ├── _range_cells.py        # `range_cells` mid-block resume/stop acceptance harness
    │   └── tests/
    │       ├── test_decoder_smoke.py       # package unit test
    │       ├── test_wp_synthetic_fault.py  # WP fault continue-to-budget test
    │       └── test_wp_tlb_cold_capture.py # WP TLB-cold code-page capture test
    └── tests/                          # sibling shell-out harnesses
        ├── run_roundtrip.sh       # default smoke shell-out
        ├── tagged_ptr_addr.sh     # aarch64 tagged-pointer cross-compile smoke
        └── large_scale.sh         # large-scale / long-running smoke

``contrib/plugins/champsim_tracer/tests/golden_net.py`` (a sibling of
``validator/``, not inside it) captures and re-checks byte-for-byte
golden ``.cst`` / SVG output; ``full``'s ``quick.golden`` check drives
it (see :ref:`Unified runner <validator-full>` below).

What it does
------------

Every run follows a five-stage pipeline:

#. **generate** — build a randomized CFG from a fixed seed, emit
   per-ISA assembly + a ``.meta.json`` describing every block's
   expected memops, register sets, branch outcomes, and wrong-path
   chains.
#. **build** — assemble and statically link the program with
   ``-nostdlib -nostartfiles`` so the trace contains only generated
   code (no libc / dynamic loader noise).
#. **trace** — run the binary with the plugin loaded and
   ``memdata=1[,regdata=1]``.  A user-mode run under ``qemu-<isa>``
   drives the window from a clock:
   ``trace_window=icount:start=0+stop=N``, or
   ``trace_window=symbol:...`` / ``trace_window=simpoint:...``.  A
   system-mode run under ``qemu-system-<isa>`` is a marker window —
   the only window system mode accepts — opened by the workload's own
   marker sequence.
#. **analyze** — post-process the binary to extract PC spans per
   block, the helper-leaf instruction count, and stable
   ``ground_truth`` records; annotate ``meta.json`` in place.
#. **validate** — load the ``.cst`` and the annotated ``meta.json``,
   run every named check, and emit a summary report.

The default ``all`` subcommand runs the whole pipeline end-to-end.
Specialised sub-commands (``simpoint_test``, ``thread_test``) run a
narrower pipeline tailored to a specific tracer feature.

Quickstart
----------

.. code-block:: console

   $ cd contrib/plugins/champsim_tracer/validator
   $ python3 -m champsim_tracer_validator all \
         --seed 0x0102 \
         -o out/ \
         --isa x86_64 --isa aarch64 \
         --build-dir ../../../../build \
         --regdata

This generates two programs (``x86_64`` and ``aarch64``), traces them
both, validates each, and prints a per-ISA summary.  All seeds are
deterministic; the same ``--seed`` regenerates byte-identical asm.

A typical full-coverage invocation across all four ISAs:

.. code-block:: console

   $ for ISA in x86_64 aarch64 riscv64 mipsel; do
       python3 -m champsim_tracer_validator all \
           --seed 0x0102 -o out/ --isa "$ISA" \
           --build-dir ../../../../build \
           --diamonds 4 --side-len-min 2 --side-len-max 3 --stop 50000 \
           --regdata --iframe-rate 3 --coverage
     done

Flags worth knowing:

``--regdata``
   Trace with ``regdata=1``.  Enables per-insn destination-register
   snapshots and the FID_METAFLAGS side-channel; required for the
   ``metaflags`` and ``regdata_reconstruction`` checks to do anything
   beyond a "skipped" info message.

``--coverage``
   Inject the ``_probe_specs.py`` coverage probes (single-instruction
   blocks targeting every ISA-supported GenericOpcode / BranchType
   combination) onto the entry-side of the CFG.  Off by default
   because probes broaden the assertion surface and add a few hundred
   templates per run.

``--iframe-rate N``
   Override the plugin's ``iframe_rate`` (default 100000).  Small N
   (3–10) exercises the IFRAME-validation path on short traces.

``--start-symbol NAME``
   Use ``trace_window=symbol:name=NAME+simulation=<stop>`` instead of
   the default icount-based window.  The validator trims
   ``correct_path`` to start at ``NAME``'s block, so symbol-based
   traces still get full CP / WP validation.

``--depth N``
   Wrong-path budget passed through to the plugin as ``wpdepth=N``.
   Default ``64``.  The ``wrong_path_chains`` check trims its expected
   WP block sequence to this same instruction budget.

``--hot-iters N``
   Inject a loop region into one of the diamond sides, running for N
   iterations.  Useful for pushing the trace past short-program
   icount budgets when testing simpoint mode.  The default depends on
   the sub-command: ``0`` (no injected loop) for ``generate`` and
   ``all``, ``5000`` for ``simpoint_test`` (so the synthetic
   program runs past the second simpoint interval), and ``2000`` for
   ``churn_test`` (long enough to outlive its budget, small enough to
   stay inside the generator's CP-walk step cap).

``--system`` (with ``--kernel`` / ``--rootfs`` / ``--sys-mem`` / ``--smp``)
   Trace under ``qemu-system-<isa>`` instead of qemu-user: the
   workload is staged into an initramfs and its compiled-in marker
   opens + ASID-pins the window (``trace_window=marker``, which is the
   only window system mode accepts — the clock-driven ``icount`` /
   ``symbol`` / ``simpoint`` drives above are user-mode windows).
   Implies ``--marker`` at generation, which also injects the close(-1)
   syscall probe and the sysinfo fault probe right after the marker.
   ``--smp N`` boots N vCPUs; body entries carry the GUEST-THREAD
   identity as ``thread_id`` (resolved from the kernel per-thread
   pointer, stable across vCPU migration), never the vCPU index — the
   vCPU is absent from the wire.  The guest console (plus the plugin's
   stderr) is captured to ``<base>.console.log`` and the segment-close
   coverage line is asserted after the run.

``--attach``
   System-mode variant that opens the window by *injection* instead of
   a compiled-in marker, exercising the path an unmodified binary has
   to take.  :program:`cst_attach` is cross-built for the guest ISA
   (statically, with that ISA's toolchain), staged into the initramfs
   as ``/bin/cst_trace``, and handed the workload to exec under
   ``ptrace``; it pokes the marker sequence into the workload's entry
   point, runs it, restores the original bytes and registers, and
   detaches.  The workload is generated with **no start marker** — the
   in-window probes and the END marker are unchanged — so a run that
   produces a trace at all is evidence the injection worked, and one
   whose injection fails stops rather than falling back.  Mutually
   exclusive with a custom guest init (the injector owns the
   workload's exec).  An ISA whose cross compiler is not installed is
   skipped, not failed.

Sub-commands
~~~~~~~~~~~~

``all`` (the workhorse)
   generate + build + trace + analyze + validate, one pipeline per
   ``--isa``.

``generate`` / ``build`` / ``trace`` / ``analyze`` / ``validate``
   The individual stages, exposed for debugging.  Useful when an
   iteration of ``validate`` reveals a bug and you want to re-run
   just that stage without rebuilding.

``simpoint_test``
   :ref:`Segmentation test <validator-segmentation>`.  Builds one
   binary with a long hot loop, writes a simpoint-selection file
   picking two intervals, traces them via ``trace_window=simpoint:``,
   and validates each per-segment ``.cst`` independently.

``thread_test``
   :ref:`Multi-thread test <validator-multi-thread>`.  Builds the
   hand-written 2-thread program for the requested ISA (parent +
   child both run identical atomic-RMW loops), traces it, and
   asserts both threads are visible.  With ``--system --smp N`` the
   same clone pair runs marker-pinned inside a booted guest, and the
   assertions run against the guest-thread identities the tracer
   resolves from the kernel per-thread pointer — the vCPU is absent
   from the wire, so they hold however the scheduler placed the pair.

``churn_test``
   :ref:`Multi-process churn test <validator-churn>`.  System-mode
   only: the guest's init forks through short-lived unmarked
   processes before and while the marked workload runs, rolling the
   ASID space over while the pinned window is open; asserts the pin
   followed only the marked process.

``full``
   :ref:`Unified runner <validator-full>`.  ONE command that runs a
   fixed battery of checks across four tiers, reduces the whole run
   to a single JSON summary and a single exit code, and enforces that
   every registered plugin option / wire record / cross-cutting
   behaviour is claimed by at least one check.  This is the
   release-gate entrypoint.

``mutation``
   :ref:`Mutation testing <validator-mutation>`.  Adversarial
   strictness proof: damages a known-good trace one well-defined way
   at a time and asserts a specific check catches each corruption.
   Runs standalone, or in-process from ``full``'s
   ``features.mutation_strictness`` check.

``range_cells``
   Targeted mid-block resume/stop cells: exact executed-range
   assertions (:doc:`format` §4.2a) at the five capture boundaries
   that produce partial entries — a user block split by a demand
   fault, an icount window billing exactly its budget, an END-marker
   close mid-block, a REP invocation interrupted mid-flight, and a
   wrong-path chain cutting its last block at the wpdepth remainder.

   A sixth assertion, ``cut_head_fault``, is a universal invariant
   over the system stream rather than a staged cell: no chain may
   complete at a non-branch instruction unless the next entry in its
   context starts at that template's fall-through pc.  It is the wire
   signature of a *translation-cut* faulting head — a translator that
   stops at an instruction it knows will raise (a MIPS
   coprocessor-unusable FPU store) hands the fault fold a template
   ending at the faulting instruction, and a merge continuation
   bounded by it silently swallows the resumed instructions past the
   cut.  The falsifier fixture is that exact pre-repair stream shape.

   Two cells stage their own subjects rather than depending on the
   supplied run directories to happen to contain one.
   ``budget_close`` re-traces the user workload under a window sized,
   from the exit-closed trace's own decoded ranges, to provably land
   mid-block.  ``rep_split`` assembles and boots a dedicated x86-64
   system workload — a marker-bracketed ``REP STOSB`` whose
   destination crosses into a never-touched page, so the guest kernel
   demand-faults mid-loop — and asserts the fan-out survived the
   interruption: iteration entries on both sides of the excursion,
   and the per-iteration stores tiling the staged span exactly (the
   architectural count, never the delivered-callback count).

   ``marker_end`` needs the END-marker pcs, and takes them from a
   carrier the wire already has: the templates section publishes
   every instruction's byte encoding, and the END sequence's
   encoding is fixed by ``champsim_marker.h`` (parsed, not
   restated), so the sequence is located in the trace's own template
   bytes.  A partial witness — a capture that stopped inside the
   sequence — is placed by contradiction against the known
   neighbouring bytes, with a structural prefix tie-break for the
   pair-encoded markers (any close removes a *suffix*, so the true
   placement's witnessed slots start at slot 0 with no hole), and an
   ambiguous placement fails loudly rather than guessing.

   The cell then asserts the deferred-close contract of
   :doc:`format` §4.2a on the final user entry: it is the WHOLE
   sealed block the marker fired inside — ``bb_stop`` equal to the
   template's ``num_insns``, the block ending at its own terminating
   branch, and the firing instruction inside the published range —
   and the close billed exactly what it published (``user insns
   actually executed`` == ``user insns emitted to the wire``, read
   from the run's own ``stats.log``).  A truncated final entry, an
   entry for a block *after* the marker's own, an unterminated block,
   a billed/published mismatch, and a missing stats pair each fail.

   ``--selftest`` proves each assertion rejects its falsifier (the
   pre-range merged/overshooting shape, a lost REP iteration, an
   unwitnessed marker) on synthetic fixtures — including both
   ``thread_end`` falsifiers (a context's final entry missing the
   stamp; a stamp lying mid-stream), all three END-marker derivation
   directions (a full byte-witnessed sequence; a single-instruction
   witness placed by contradiction; a pair-encoded partial witness
   resolved by the prefix rule, against a genuinely ambiguous pair
   that must be refused), and all four ``marker_end`` directions
   above.  The live cells are the acceptance harness for split
   emission: a writer that still merges, overshoots, or drops
   retired REP iterations fails them by design.

``plugin_load``
   Proves the built plugin can be **loaded**, not merely linked.  A
   shared object may carry an unresolved symbol and still link;
   whether that is fatal is decided at load, and QEMU opens plugins
   with ``g_module_open(..., G_MODULE_BIND_LOCAL)``, which without
   ``G_MODULE_BIND_LAZY`` is ``RTLD_NOW`` — every symbol resolves
   before ``qemu_plugin_install`` is looked up.  A standalone
   ``dlopen`` cannot stand in for this: the plugin's
   ``qemu_plugin_*`` symbols come from the QEMU executable, so a
   standalone load fails on a perfectly good object.  The check runs
   a real QEMU from the build dir against the plugin — a system
   target under ``-M none``, a user target with no guest binary,
   both a fraction of a second and neither needing a guest image —
   and reads the verdict from the output rather than the exit
   status, which is nonzero either way.

   Each probe first proves it can report the failure it is looking
   for, by being run once against a plugin path that cannot exist.
   A binary that stays silent for a plugin that is not there cannot
   speak for one that does not resolve, and is discarded rather than
   trusted; if none survives, the check fails, because a question
   that could not be asked has not been answered.  ``cmd_trace``
   asserts it once per build before running anything.

``stall_scan``
   Replays a labelled corpus of instruction-sampler trajectories
   (``<cell>.sample.tsv`` + ``<cell>.status.txt``, optionally
   ``<cell>.stats.log``) and re-proves the workload-progress stall
   detector described in :ref:`troubleshooting-escaped-stall`.  It
   scores every cell from architectural counts only, reports the
   distribution over the cells that closed against the ones that did
   not, exercises the shipped in-suite gate over the same cells'
   ``stats.log``, and exits nonzero when the instrument misses a
   known-wedged cell, flags more than a stated fraction of the rest,
   fires on nothing at all, or cannot find a corpus.  It is the
   detector's positive control: an instrument whose ability to fire
   is unproven has no standing when it is silent.

.. _validator-full:

Unified runner (``full``)
--------------------------

``full`` is the single entrypoint that exercises everything else in
this document plus a battery of coverage no other sub-command
reaches on its own, and collapses the result into one JSON summary
and one exit code.  It is the release gate: design-doc gate summaries
(e.g. ``fault_merge_wp_rearch_plan.md``'s per-stage table) cite it
verbatim as ``validator full`` green (``pass=N fail=0 ...``) alongside
the golden-trace nets.

.. code-block:: console

   $ python3 -m champsim_tracer_validator full \
         --build-dir ../../../../build \
         -o /mnt/md0/QEMU/cst_runs/valunify

Reliability contract:

* every check gets its **own uniquely-named work directory** under
  ``--work-root``, so nothing collides across a run;
* every check **self-cleans** any qemu process it leaked, scoped to
  its own work root, on the way out (``pkill`` best-effort);
* unless ``--no-wait``, the whole run first loop-waits for a **quiet
  host** — zero foreign ``qemu`` processes by COMM name, polled every
  15s up to ``--max-wait`` — because the golden-byte check and
  system-mode timing produce false failures under concurrent host
  load;
* the whole process tree runs under a 24 GiB ``RLIMIT_AS`` cap.

Arguments:

``--build-dir``
   QEMU build directory (``qemu-<isa>``, ``qemu-system-<isa>``, the
   plugin, and the offline tools).  Required.
``-o`` / ``--work-root``
   Output root (default ``/mnt/md0/QEMU/cst_runs/valunify``); each
   check gets a unique subdirectory under it.
``--tier`` (repeatable)
   Restrict the run to one or more of ``quick`` / ``system`` /
   ``multiproc`` / ``features``.
``--only`` (repeatable)
   Restrict the run to specific check ids, e.g. ``--only
   features.smc --only features.devio``.
``--seed``
   Base seed for every generated workload in the run.
``--no-wait`` / ``--max-wait``
   Skip, or bound (default 3600s), the quiet-host wait above.
``--dry-run``
   Build the check table and coverage map, and enforce the
   registration gap below, without running anything — a fast sanity
   check on the registry itself.
``--summary-json``
   Also write the JSON summary to this path.  It is always written to
   ``<work-root>/full_summary.json`` regardless.

Coverage enforcement
~~~~~~~~~~~~~~~~~~~~

Every plugin option, wire record, offline-tool invocation, and
cross-cutting behaviour the tracer supports is registered in a
feature table (78 ids, spanning the ``opt:*`` / ``wire:*`` /
``tool:*`` / ``behavior:*`` namespaces) and mapped to the
check id(s) that exercise it.  ``full`` fails — independent of
whether any check itself failed — if a registered feature has **zero**
exercising checks (a *static gap*: the registry rotted out from under
a real feature) or if a check claims a feature id that was never
registered (a typo in the check's own ``features=[...]`` list).  Each
run's summary additionally reports *runtime-uncovered* features: ones
whose only exercising check(s) did not pass this particular run — a
softer signal than the static gap, since a flaky or currently-broken
check can runtime-uncover a feature the registry still statically
claims.

Tiers
~~~~~

Checks are registered with :func:`Check(id, tier, desc, features, fn,
known_issue=...)`.  A check whose ``known_issue`` is set is
**non-gating**: a failure is remapped to ``XFAIL`` — reported loudly
in the summary, but it does not flip the run's exit code.  This is
reserved for a confirmed upstream break or a genuinely
timing-sensitive scenario that would otherwise produce a false RED
under host contention; two ``multiproc`` checks use it (below).

**quick** — 9 checks.  Mostly the ``all`` pipeline documented above,
run under fixed flags per ISA, plus a handful of narrow one-off smoke
checks and a byte-for-byte golden regression net:

``quick.user_x86_64`` / ``quick.user_aarch64`` / ``quick.user_riscv64`` / ``quick.user_mipsel``
   ``all`` with ``--diamonds 8 --coverage --regdata --hot-iters 200``,
   one per ISA — user-mode 4-ISA correctness.
``quick.iframe``
   ``all --iframe-rate 500 --regdata`` (x86_64) — IFRAME resync
   cadence under an aggressive override.
``quick.wpprune``
   ``all --wpprune 2`` (x86_64) — cold-branch wrong-path pruning.
``quick.symbol_start``
   Drives ``trace_window=symbol:`` directly (not through ``all``):
   asserts a segment actually opens at the requested symbol
   occurrence and that the occurrence counter advances
   (``occurrence=2`` opens strictly later than ``occurrence=1``).
``quick.tbflush``
   ``all --tb-size 1 --diamonds 16 --hot-iters 100`` (x86_64) —
   template reclamation across a mid-trace ``tb_flush``.
``quick.golden``
   Drives ``tests/golden_net.py check`` against a fixed canonical
   work-root (the guest stack base — and hence wire bytes — shifts
   with the work-root path length, so this check reuses one exact
   path rather than its own per-check directory) — byte-for-byte
   wire and ``cst_visualize`` SVG regression.

**system** — 11 checks.  ``system.churn_x86``,
``system.churn_mipsel``, ``system.thread_x86``, ``system.thread_mipsel``
and the four ``system.clock_progress_<isa>`` checks literally invoke the
``churn_test`` / ``thread_test`` sub-commands documented above under
fixed arguments; cross-reference those sections for what they assert.
``system.thread_mipsel`` is the ``thread_strand`` gate's home ISA: a
narrow ASID folds the pinned process's every strand into one asid, so two
vCPUs' kernel work shares a context the moment their thread ids agree.
``system.user_x86``, ``system.smc_x86``, and ``system.attach_mipsel``
add coverage no other sub-command exposes:

``system.user_x86``
   ``all --system --marker --coverage --regdata`` under ``-cpu max``
   — the full-oracle marker/pin battery (ASID-switch records, kexc
   excursion ownership, syscall/fault nesting, user-code identity)
   against a real system boot.
``system.churn_x86`` / ``system.churn_mipsel``
   :ref:`Multi-process churn test <validator-churn>`, x86_64 and
   mipsel (narrow 8-bit ASID).
``system.thread_x86``
   :ref:`Multi-thread test <validator-multi-thread>` under
   ``--system --smp 2``.
``system.smc_x86``
   Self-modifying code mints revisions under the marker window /
   pinned ASID (x86 system boot), across a shape-changing rewrite
   (2 instructions re-emitted as 3 at one ``start_pc``).
``system.clock_progress_x86_64`` / ``_aarch64`` / ``_riscv64`` / ``_mipsel``
   The guest's clock keeps advancing across wrong-path excursions.
   A guest whose clock dies stops taking interrupts and spins in the
   kernel; it does not crash, and the tracer records the spin
   faithfully, so every structural oracle passes on a well-formed
   trace of a wedged machine.  Three symptom detectors run instead:
   a window that closes ``UNDER`` budget, a traced/user instruction
   ratio past 20 once the window has covered at least 5000 user
   instructions (healthy runs sit between 1 and 8.5), and a
   user-instruction clock that stops advancing in wall time.  The
   covered-count floor exists because fixed per-segment overhead
   (guest boot, marker injection, early scheduling) dominates the
   ratio below it — a window that legitimately covers only a few
   hundred instructions before closing (``system.attach_mipsel``'s
   shape) reads as a multi-hundred-x "stall" by construction, not
   because anything froze; every real stall on record instead closes
   ``UNDER`` at a covered count orders of magnitude past the floor,
   so it is caught either way.  The first two are asserted by
   ``_check_segment_coverage`` — so every system-mode check in the
   suite carries them — and the third by a live watchdog in the
   system trace path, which also bounds a wedged run's cost, since a
   spinning guest never exits on its own.

   None of the three knows anything about timers or interrupt lines,
   which is the point: they detect the symptom, so a clock source
   nobody thought to reconcile cannot slip past them.  Run on all
   four ISAs because the class recurred three times as per-ISA point
   patches, and the reason the suite stayed green through a 19%
   aarch64 stall rate is that the system tier booted only x86_64 and
   mipsel.  Uses the churn guest under the full system option set —
   a gate for a clock bug has to run the configuration in which the
   clocks are touched.
``system.attach_mipsel``
   ``all --system --attach`` on mipsel — the ptrace-injected marker
   (:program:`cst_attach`'s ``PTRACE_PEEKUSER``/``POKEUSER`` backend)
   opens the window for a workload with no compiled-in marker; a run
   that produces a trace at all is the check, since only the
   injection can have opened it.  The only standing gate that reaches
   the peek/poke backend — the other three ISAs' fixed-width
   ``PTRACE_GETREGSET`` backends are exercised by ``--attach`` runs
   outside the gated battery.

**multiproc** — 3 checks.  Genuinely new coverage, folded in from
:mod:`_multiproc` (three multi-ASID harnesses that used to live
outside the repo as standalone scripts):

``multiproc.trace_all_x86``
   ``policy=trace-all`` vs ``policy=latch`` differential: trace-all
   must capture a CONCURRENT unmarked peer's user code; latch must
   render it invisible.  **Non-gating** (``known_issue``) — the
   unmarked peer must be scheduled by the guest *inside* the marked
   window to be captured, which the host cannot guarantee under
   concurrent load, so a miss is a scheduling artefact rather than a
   wire fault; the latch-differential half is still a hard assertion.
``multiproc.latch_mips``
   Narrow-ASID (mipsel, 8-bit) two-process latch: two MARKED
   workloads latch independently, anchored by physical-code-page
   identity rather than the aliased ``EntryHi.ASID`` value; a
   ``--churn`` variant rolls the 8-bit ASID space to prove
   recycle-no-cross-attribution.
``multiproc.dead_latch_x86``
   A marked peer is ``kill -9``'d mid-window with no END marker; the
   dead-latch detector must age it out so the segment still closes
   cleanly.  ``latch_timeout=750ms`` — small enough that ordinary
   guest scheduling contention can never be mistaken for the timeout
   racing progA's own runtime (the old 3000ms default's failure mode),
   large enough that live-root scheduling jitter can never be
   mistaken for death.  The assertions are causal: the plugin's own
   "marker opened additional window ... (2 owned)" stderr line (never
   routed through the guest UART, so it survives the abrupt
   ``exit(0)`` that follows the last window closing) proves the peer
   was genuinely alive before it died, and the "dead-latch close"
   line is checked against that *same* asid.  See "Dead-latch
   determinism" in ``VALIDATION.md`` for the full design rationale.

**features** — 20 checks.  Plugin options and wire records that no
``quick`` / ``system`` / ``multiproc`` check happens to exercise:

``features.simpoint``
   :ref:`Segmentation test <validator-segmentation>` — per-simpoint
   segment independence and cross-segment consistency.
``features.branch_verify``
   ``cst_decode --verify-branch`` direction/target cross-check
   against a traced (not validated) run: each branch outcome against
   the entry where its context resumes the encoded target, with every
   control-flow diversion tallied by the signal that excused it.
``features.physaddr``
   Per-memop physical-page capture (``physaddr=1``, system mode).
``features.devio``
   Disk-I/O bracketing records (virtio-blk, system mode): a pairing
   oracle (every STOP pairs a prior START) plus an exact payload
   oracle (R/W, byte count, LBA match the workload's known request
   list).  Needs a guest kernel with ``CONFIG_VIRTIO_BLK=y`` **built
   in** (not ``=m`` — the busybox guest has no modprobe/hotplug wiring
   to pull in a module), or the probe reports the ``NO_VDA`` skip.
   ``_devio_kernel()`` looks for that kernel at a conventional path,
   ``vmlinuz-devio`` next to the ISA's default system-mode kernel
   (same ``SYSTEST_ROOT`` layout as ``default_kernel``); a
   ``CST_DEVIO_KERNEL`` environment override takes precedence over
   both for a maintainer who wants to point at a kernel elsewhere
   without moving every OTHER system-mode check off the default one.
``features.devio_attrib``
   Exact-owner disk-I/O attribution: two CONCURRENTLY marked
   processes (``-smp 2``, disjoint LBA bands) must each own only
   their own band's ``DEVIO_START`` records.  Same kernel requirement
   as ``features.devio``.
``features.faults_interrupts``
   Synchronous-fault exclusion plus asynchronous-interrupt capture
   (``faults=0`` / ``interrupts=1``, system mode).
``features.tagged_ptr``
   aarch64 tagged-pointer data-is-address heuristic (skips cleanly
   without a cross-compiler).
``features.wp_fault``
   WP execution-time fault continues to budget (deterministic
   garbage past the fault, not a poison/kill).
``features.wp_tlb_cold``
   WP fetch of a valid-PTE but TLB-cold code page captures real
   bytes; a no-PTE target terminates the chain (system mode).
``features.mops_memops``
   AArch64 FEAT_MOPS bulk transfers reach the memory instrumentation
   on the correct path.  ``SETP``/``SETM``/``SETE`` and
   ``CPYP``/``CPYM``/``CPYE`` move memory from inside a TCG helper
   with a host ``memset``/``memmove``, never through a ``qemu_ld`` /
   ``qemu_st`` op, so without the base's ``arm_plugin_bulk_mem_cb``
   (see :doc:`qemu_modifications`) they record no memory access at
   all — and glibc routes every ``memcpy``/``memmove``/``memset``
   through them on a guest advertising ``HWCAP2_MOPS``.  The check
   issues both triples directly, so nothing depends on a libc ifunc
   choice, over page-aligned buffers at a size — two whole pages plus
   64 bytes — that puts work on all six instructions.  The assertion
   is a *tiling* one, which pins addresses and sizes and not just a
   count: the ``SET`` triple's stores must cover the destination
   range exactly (contiguous, no gap, no overlap, every access
   naturally aligned and at most 16 bytes), and the ``CPY`` triple's
   loads and stores must likewise tile the source and the
   destination.  Against a base without the fix all six instructions
   are silent and every tiling is empty.
``features.dc_zva_memops``
   AArch64 ``DC ZVA`` reaches the memory instrumentation on the
   correct path *and* is modelled as the block store it is.  The
   instruction zeroes a naturally aligned block whose size comes from
   ``DCZID_EL0.BS``, through the same helper-internal host ``memset``
   the FEAT_MOPS families use, and Linux's ``clear_page`` is built on
   it — so on a system-mode trace it is a large share of all store
   traffic.  The check zeroes four consecutive blocks, reading the
   block size from the guest's own ``DCZID_EL0`` rather than assuming
   64 or 512 bytes, and asserts the same *tiling* the MOPS check does
   over the whole run.  It separately asserts that the instruction's
   template declares a store lane: Capstone gives ``DC ZVA`` no memory
   operand at all, and without the boundary correction (see
   :doc:`qemu_modifications`) reported stores land on an instruction
   the trace declares incapable of touching memory.  The two halves
   fail independently — a base with neither records no accesses at
   all, and a base with the instrumentation but not the classification
   fails ``cst_decode --strict`` instead.
``features.string_memops``
   x86 ``REP`` string instructions fan out per architectural iteration
   with the right per-iteration memop count, and the operand model
   matches what each instruction really reads and writes.  A
   ``REP``-prefixed string op derives its per-iteration memop count
   from the Capstone access flags on its memory operands, so a lost
   flag makes that count zero — and a zero count disables the fan-out
   entirely, collapsing the whole repeated operation onto one body
   entry whose memops its template says it cannot perform.  The check
   runs ``cmpsb``, ``cmpsl``, ``scasb``, ``lodsb``, ``stosb`` and
   ``movsb`` over page-separated buffers and asserts, per instruction,
   that every body entry carries exactly one iteration's memops, that
   the entry count equals the iteration count, and that the accesses
   tile each buffer exactly.  It also pins the static lane counts for
   the scalar ``ROUNDSS`` / ``ROUNDSD`` memory form (a real load that
   was being dropped) and for the multi-byte ``NOP`` (a phantom load
   lane on an instruction that touches no memory), and requires
   ``cst_decode --strict`` to be clean.  Against a base without the
   corrections in :doc:`qemu_modifications` the ``cmpsl`` fan-out and
   the lane assertions fail.
``features.options_smoke``
   Direct qemu-user drive of the long-tail options no other check
   sets (``histogram``, ``wp_memdata``, ``wp_regdata``,
   ``program``/``comment``); asserts the trace decodes clean.
``features.mutation_strictness``
   The :ref:`mutation <validator-mutation>` matrix, run in-process.
``features.final_entry_memops``
   The segment's **last** body entry keeps its memory operands.
   Body entries are emitted one TB late, so an entry flushed on a
   path that runs before its instructions execute carries no memops
   at all — one entry per segment, and invisible to every byte-level
   gate (``cst_audit``'s rollup reconciles the records that *are*
   present, and the impossible-attribution lint only rejects a memop
   on a memop-incapable slot, never a memop-capable slot with no
   memop, which predication and a zero-count ``REP`` make legal).
   The check forces a genuine deferred window close — an ``icount``
   stop reached mid-run, with the plugin reporting the segment ``OK``
   rather than ``UNDER``/``END`` — then requires the trace's final
   entry to land on a true BB that statically accesses memory and has
   executed before with an invariant memop shape, and asserts the
   final execution carries that same shape (count, and which
   instruction slot performs which access).  Self-calibrating: the
   oracle is the trace's own repetition, so there is no per-workload
   expectation to maintain.  A window whose final entry cannot supply
   the oracle is retried at a different stop, and a sweep that never
   finds one fails rather than passing vacuously.  All four ISAs.  The
   same assertion runs inside ``validate()`` as
   ``segment_final_memops``, where it is silent on traces that close
   at the guest's exit.
``features.reg_snap_accounting``
   Oracle 1 of the two general D4-class completeness checks (see
   ``features.final_entry_memops`` above for the specific mechanism
   that motivated both).  The plugin already counts a completeness
   invariant at every seal walk — ``Stats.reg_snap_slice_dropped`` /
   ``Stats.reg_snap_leak_trimmed`` (champsim_tracer_stats.h) — but
   neither counter ever reaches the wire; they exist only in the
   plugin's stderr summary and its ``<outfile>.stats.log`` sidecar, so
   no byte-level check on the trace file can see them.  This check
   traces a short workload per ISA, reads the counters back out of the
   sidecar, and asserts that **no slice was dropped** — the drop count
   and the number of register deltas it discarded must both be zero,
   with the end-marker-close subset included in the total rather than
   excused from it.  A trim is a recovery and is reported for context,
   not balanced against the drops; a sidecar that carries no
   end-marker-close or discarded-delta breakdown fails the check rather
   than being read as zero.  The same
   two counters, and the same verdict, are available offline to a
   consumer holding both files via ``cst_audit --stats-log=...`` (see
   :doc:`decoder`, *COMPLETENESS (Oracle 1)*).
``behavior:memop_bimodality`` (Oracle 2)
   The general form of the D4 signature, generalised past
   ``features.final_entry_memops``'s single-last-entry special case:
   for each memop-capable template, tally how many of its CP
   executions realised at least one memop versus how many realised
   none.  A template that is overwhelmingly nonzero with only a SMALL
   minority of zero-memop outliers is flagged — any future memop-loss
   bug with this shape is caught, not just the exact D4 mechanism, and
   not only when the loss happens to land on the segment's last entry.
   A template that is legitimately bimodal AT SCALE (heavy predication,
   a REP loop empty as often as not) is not flagged; the zero-rate
   threshold below which executions count as "a small minority of
   outliers" is tunable.  A PARTIAL execution — an entry whose declared
   range (:doc:`format` §4.2a) stops short of the template, so it never
   had the chance to realise the full memop complement — is excluded
   from the population entirely, since the wire already explains its
   shortfall; the silent loss the oracle hunts declares no partial
   range.
   Implemented twice, deliberately kept in sync:
   ``cst::MemopBimodalityLint`` (``tools/cst_lint.h``) feeds
   ``cst_audit``'s always-on ``MEMOP BIMODALITY`` report section
   (``--bimodal-min-execs`` / ``--bimodal-max-outlier-rate`` /
   ``--bimodal-off``; see :doc:`decoder`), and ``validator.py``'s
   ``_check_memop_bimodality`` runs inside every ``validate()`` call as
   the ``memop_bimodality`` check — so it rides along with every
   ``quick.user_*`` invocation of ``full`` (tagged onto the
   ``core_user`` feature list) without a dedicated check of its own.
   Mutation-tier teeth: ``mid_entry_memops_dropped`` (see
   :ref:`validator-mutation`) strips the memops from one non-final,
   otherwise-invariant execution — proving the check catches the
   general shape, not merely a positional special case.
``features.wrong_path_coverage``
   ``static_templates=1`` fall-through / BTB coverage oracle across
   all four ISAs (minted-alternate blocks, deepened by
   ``static_depth``), with a minting-off run proving the oracle has
   teeth.
``features.isa_crosscheck``
   The one check in the battery whose ground truth comes from outside
   the tracer.  Every other oracle here reads the same Capstone-derived
   metadata the tracer does, so a decoder defect corrupts the trace and
   the oracles agree with the corruption; Intel PIN broke that circle on
   x86 and found five real defects, and it reaches none of the other
   three ISAs.  ``isaxcheck`` feeds identical encoding bytes to the
   tracer's own decode boundary — ``cap_disas_raw_detail()`` in
   ``disas/capstone.c``, Capstone plus every correction applied on top —
   and to the LLVM MC layer, a separately maintained decoder and
   instruction-description database, then buckets every disagreement by
   ``(class, mnemonic, difference)`` signature.  Five classes are
   compared: decode agreement and instruction length; operands the
   boundary cannot model or that carry no access bits; memory presence
   and direction against ``mayLoad``/``mayStore``; branch taxonomy; and
   the architectural register read/write sets, with the plugin's own
   ``include_implicit_regs`` policy modelled so that what is compared is
   what the dependency model would actually record.

   The sweep is exhaustive over the opcode-bearing bit space — 164 M
   AArch64 encodings, 16.8 M RISC-V including every compressed halfword,
   151 M MIPS, and 1.25 G x86_64 — 1.58 G in all, a couple of minutes for
   all four ISAs at ``--jobs=16``.  That cheapness is the point: it is
   affordable on every Capstone bump, which is what keeps the
   ``disas/capstone.c`` workarounds retirable instead of permanent.

   x86_64 dominates because its encoding is the one with several
   independent variable dimensions rather than one fixed word, and each
   was closed only after its blind spot was measured against a traced
   population: ModRM.reg and ModRM.rm (both carry opcode), REX as
   sixteen values rather than one spelling, ModRM.mod's two missing
   addressing forms, the whole of VEX, and — most recently — SIB.index
   and SIB.base, which 12.25% of a traced x86 population's dynamic
   weight passes through and which were sampled at four of sixty-four
   values before.  ``sweep_x86()`` in ``isaxcheck.cc`` carries the
   measurement for each, including the one dimension deliberately left
   pinned and why.

   **The register fill sets are coverage, not convenience.**  Each sweep
   walks the opcode-bearing bits exhaustively and fills the register
   fields from a short list, and that list has one rule to satisfy: *any
   register value that selects a different decode must be in it.*  A
   register field is usually data, but where a particular value picks an
   alias, a different printed form, or a different instruction outright,
   omitting the value puts the whole form outside the swept space — and a
   defect there is not something the gate missed, it is somewhere the
   gate never looked.

   AArch64 ``ret`` is the worked example: it is the alias of ``RET X30``
   and no other ``Rn`` reaches it, so the boundary's loss of the link
   register read on the most executed control transfer in any AArch64
   trace sat outside the sweep through every green run until ``Rn = 30``
   was added.  The same shape holds elsewhere, and each fill set names
   its case: RISC-V's uncompressed ``ret`` is ``jalr x0, x1, 0`` (the
   compressed sweep covered ``c.jr ra`` for free, which is exactly why
   the 32-bit form went unnoticed — the alias *looked* swept); MIPS
   prints ``JALR`` with ``rd = 31`` in its two-operand form; and x86's
   ``ModRM.reg`` is an opcode *extension* on the group opcodes, so
   sweeping two of its eight values left six members of every group —
   SUB, AND, XOR, CMP, the shift family, NOT/NEG/MUL/DIV,
   INC/DEC/CALL/JMP/PUSH — and the entire x87 escape space unreached.

   Closing those found a defect in this tool as well as in the space it
   measures: its MIPS normaliser dropped a coprocessor index by keeping
   the *last* digit, so COP0 register 31 read as ``cop1`` and every
   coprocessor register above 9 was compared against the wrong one.  Ten
   allowlist entries existed only to excuse that, and the dead-rule
   report retired all ten.  Because the Capstone side
   is the *boundary*, a workaround that works shows up as the ABSENCE of
   a disagreement, and one that has become unnecessary keeps the gate
   green — ``capstone_workaround_probe`` answers the complementary
   question of whether it can now be deleted.

   **The subtarget gap, and why the gate measures its own blindness.**
   A comparison against a second decoder is only as wide as the narrower
   decoder's configuration.  When the LLVM subtarget describes less of
   the ISA than the Capstone mode does, two things happen at once, and
   the second is the dangerous one: the report fills with "LLVM was not
   told about this extension" — 84% of the AArch64 findings, at one
   point — and every encoding LLVM *rejects* is one the register, memory
   and branch comparisons never run on at all, because a rejection
   short-circuits the whole compare.  A too-narrow subtarget does not
   merely add noise; it removes coverage, silently, in exactly the space
   the noise is drawing attention away from.

   So the gap is a first-class measurement.  ``isaxcheck`` reports
   ``subtarget_gap=<signatures>/<encodings>`` on its summary line — that
   number is the size of its own blind spot — and it enforces two rules
   that keep the number honest:

   * a subtarget-gap signature (class ``D-cs-only``) can only be
     allowlisted by an **exact** entry.  A wildcard there is refused at
     load time, because one ``*`` is enough to hide an entire ISA
     extension arriving in a decoder bump.
   * an allowlist entry that matches **nothing** is reported as ``DEAD``
     and fails the gate.  That is the opposite direction: when a decoder
     bump closes a disagreement, the justification standing over it
     becomes a claim about something that no longer happens.

   The maintenance action for a new gap is to widen the LLVM subtarget
   in ``kIsaTable``, not to add an allowlist line; a line is right only
   where LLVM has no feature to enable.  Under that rule ``riscv64`` and
   ``mipsel`` reach ``subtarget_gap=0/0``, and closing the RISC-V gap is
   what made the Zacas ``amocas.*`` dropped destination — a real defect,
   the same tied-operand shape Capstone loses on the RVV
   multiply-accumulates — visible at all.  ``aarch64`` keeps 28 named
   signatures because ``+all`` is already the widest subtarget LLVM
   offers, and the residue is Capstone accepting encodings the
   architecture reserves.

   Because ``kIsaTable`` now carries features LLVM must recognise,
   ``isaxcheck`` verifies every one of them against the target's own
   feature table before decoding anything, and fails naming the
   offender if one is absent: LLVM answers an unknown feature with a
   warning and an otherwise normal subtarget, which would reopen the
   blind spot in the middle of an otherwise green run.  Features whose
   spelling is version-dependent — extensions carrying an
   ``experimental-`` prefix until they ratify — live in a separate
   optional list, are probed individually, and are reported as taken or
   skipped on the summary line so a run is reproducible from its own
   output.

   GATING on any signature outside
   ``tools/isaxcheck_allow.txt``, and on any entry inside it that
   matches nothing.  Entries above that file's baseline
   block each name the disagreement, why it is not a tracer defect, and
   how to check whether it can be removed; below it, every remaining
   signature is listed individually rather than by wildcard, so a NEW
   disagreement still fails.  ``x86_64`` is swept for regression
   detection only — its independent ground truth is the PIN pairing, and
   its LLVM residual is dominated by prefix-consumption and
   flag-modelling differences that describe no defect.

   LLVM MC is an optional host dependency (``llvm-18-dev`` or newer
   supplying ``llvm-config``).  Without it meson skips the ``isaxcheck``
   target with a warning and this check fails with that diagnosis rather
   than silently passing.
``features.decode_fixups``
   The boundary is not the last word on what the trace records.  The
   plugin repairs some of what it is handed, one layer further in, inside
   ``decode_detail_to_generic()``: ``apply_isa_branch_fixups()`` restores
   the ``ra`` read RISC-V ``ret`` loses and the ``ra`` write ``jal`` and
   ``jalr`` lose — Capstone 6 hides the link register *completely* on the
   aliased forms, in neither the operand list nor the (always empty for
   RISC-V) implicit lists — and the operand walker, the dependency
   refiners and the lane-mask refiners rewrite the rest.

   Measured against the boundary alone, a repaired defect is
   indistinguishable from an unrepaired one.  That costs a false positive.
   It also means **a regressed repair cannot fail that gate**: the
   disagreement a regression reintroduces is the one the boundary
   allowlist already expects — ``riscv64 R-wr-missing jal +r#`` is sitting
   in it — so the two cancel and the run stays green while the trace loses
   its call graph.  A repair no check can see is a repair nothing holds in
   place.

   So ``isaxcheck`` reaches the other layer.  ``champsim_tracer_decode.cc``
   is compiled into it verbatim, through a small static library, and three
   modes follow: ``--layer=boundary`` (the default, and what
   ``features.isa_crosscheck`` gates on), ``--layer=fields`` (LLVM against
   the ``InsnFields`` the trace is written from, stated in the dependency
   model's own vocabulary — ``REG_LR``, not ``x30`` on one side and
   ``r30`` on the other), and ``--fixups``, the difference between the two.

   This check gates on ``--fixups``, asserted against
   ``tools/isaxcheck_fixups.txt`` **exactly, in both directions**: a repair
   that stops happening fails as a dead rule, and a repair nobody recorded
   fails as a new signature.  It needs no second decoder — it is the
   tracer measured against itself — so it also covers the encodings LLVM
   rejects, which is where a repair is least likely to be noticed
   otherwise.  140 signatures across four ISAs: the RISC-V link dataflow,
   the RVV whole-register group expansion, the trap and exception-return
   classifications no Capstone group covers, the x86 REP promotion to a
   self-looping branch, the AArch64 predicate-pair destination.

   Two entries are recorded because they are **wrong**, which is the other
   thing an inventory buys.  RISC-V ``dret``/``mret``/``sret`` receive a
   link-register read from a fixup that keys off ``BRANCH_RETURN``, and a
   privileged return resumes from ``mepc``/``sepc``/``dpc``; that is a
   phantom dependency.  The MIPS branch-and-link forms (``bal``,
   ``bgezal``, ``bgezall``, ``bltzal``, ``bltzall``) are reclassified to
   ``BRANCH_COND_DIRECT``, which loses the link a return-address stack
   needs.  The AArch64 predicate-pair entry shows the false-positive half
   of the same coin: ``aarch64 R-wr-missing while* +p#`` in
   ``isaxcheck_allow.txt`` describes a disagreement that never reaches a
   trace, because the ISA table supplies the second predicate one layer
   down.

   The register correspondence the fields layer needs is derived from the
   tracer's own classification table rather than written by hand — every
   Capstone register id the table classifies is named through Capstone,
   normalised the way both decoders' names already are, and recorded
   against what the tracer maps it to.  A token two generic ids both claim
   is kept as both and matched against either, because that ambiguity is
   the tracer splitting one architectural register across two ids rather
   than an error in the index.  AArch64 does exactly this: ``lr`` maps to
   ``REG_LR`` and ``w30``, the 32-bit view of the same register, to
   ``REG_GPR30``.  The count is reported as ``ambiguous_reg_tokens`` on
   the summary line.

   On x86_64 and riscv64, ``--layer=fields`` remains a diagnostic view
   rather than a gate: its residual against LLVM has not been triaged
   there, and a derived baseline in its place would assert only that
   nothing changed, not that anything is right.  On mipsel and aarch64 it
   **is** a gate — ``features.decode_fields``, below.
``features.decode_fields``
   The fields layer, gated, on the two ISAs where it is the only
   independent witness.  x86_64 has Intel PIN and riscv64 has Spike to
   confirm the register dependencies a trace records; mipsel and aarch64
   have neither, so an independent *static decode* of the same encodings
   is their sole external check on the dependency model — including the
   day the execution-derived register capture replaces Capstone as the
   source of that model, which is the change this gate exists to referee.

   The check runs ``isaxcheck --layer=fields --classes=MBR`` over the full
   encoding sweep on mipsel and aarch64 and gates against
   ``tools/isaxcheck_fields_allow.txt`` with the same semantics as the
   boundary gate: an untriaged disagreement fails as a new signature, and
   an allowlist row matching nothing fails as a dead rule.  The ``D``
   class is excluded because decode agreement and the subtarget gap are
   the boundary gate's property; gating them twice would double-count one
   hole.  The allowlist is not a derived baseline: every row was triaged
   into a family whose comment carries its verification (most families
   are the boundary residual seen one layer down and cross-reference the
   boundary allowlist; the genuinely fields-level families — the trap and
   MOPS branch classifications, prefetch-as-load memop modeling, the
   system-register writes LLVM's descriptions structurally cannot name —
   cite the design they assert).  Rows that record *defects* say so:
   the FEAT_LS64 register-group truncation, the ``psel`` index read and
   the LDG base-write phantom are inherited Capstone gaps named as open
   work, and they are expected to go **dead** — and demand removal — when
   the execution-derived capture lands.

   Before trusting any of that, the check proves the instrument can fire.
   ``isaxcheck --falsify=drop-src:MNEM`` erases the source set the
   dependency model recorded for one known-good mnemonic, and
   ``--falsify=add-dst:MNEM`` plants a phantom write, both injected after
   ``isax_fields_decode()`` — the exact layer a real defect would occupy.
   The check requires the healthy encoding to compare clean, and each
   falsified run to exit non-zero naming the damaged mnemonic in the
   expected class (``FR-rd-missing``, ``FR-wr-phantom``); a falsifier
   that does not fire fails the check outright, because a green sweep
   from an oracle that cannot alert is not evidence.  The single-encoding
   arms ride ``--hex`` with ``--check``, which routes the bytes through
   the same signature, allowlist and exit-code machinery as the sweep.
``features.lldet_watchdog``
   The hang detector's own fire-proof.  The tracer carries no
   detect-and-handle for the livelock/hang class — by ruling, detection
   lives in the harness — so ``lldet`` is the only thing standing between
   a wedged guest and a run that reports nothing at all.  Every "no hang"
   result the battery produces is therefore the narrower statement *the
   watchdog watched and stayed silent*, and that statement is worth
   exactly what the proof that the watchdog can speak is worth.

   The subject is the adjudicator, so the check drives it directly and
   uses no guest, no qemu and no trace.  Three arms, each a child process
   with a five-second deadline:

   - **deadlock** — a frozen child.  Zero CPU delta and zero growth must
     produce a ``DEADLOCK`` verdict and exit ``89``.
   - **livelock** — a spinning child.  A full host core with zero trace,
     console and write growth must produce a ``LIVELOCK`` verdict and
     exit ``89``.  The two arms reach the verdict through different
     branches, and livelock is the shape the class is named for, so a
     working deadlock arm vouches for nothing here.
   - **progress control** — a slow child that keeps growing its trace
     file.  It must *not* be killed, and must be observed taking the
     ``SLOW`` extension.  Without this arm the kill arms are equally
     consistent with a watchdog that kills everything it watches, which
     would empty the battery's silences of meaning in the other
     direction.

   A healthy validator cell cannot be used as this proof, and the attempt
   is instructive: ``adjudicate()`` requires a *second* sample
   ``SAMPLE_GAP_S`` after the deadline, so a cell that finishes in
   between simply exits.  Shortening the deadline against a healthy cell
   yields a sidecar showing the deadline crossed, one sample taken, no
   verdict and a natural exit — an instrument photographed in the act of
   not firing.  The condition being adjudicated is a stall, so the arms
   must stall.
``features.implicit_operands``
   An *implicit* operand is architectural state an instruction touches
   that its encoding does not name: AArch64 ``ret`` reading ``x30``,
   RISC-V ``vmerge`` reading ``v0``, every RVV instruction reading ``vl``
   and ``vtype``, MIPS ``c.eq.s`` writing an FCC and ``bc1t`` reading it,
   MIPS ``ins`` reading its own destination.  Every decode defect this
   project has found has been one of these.  This check holds a table of
   435 objdump-verified probe encodings — 169 AArch64, 146 RISC-V, 120
   MIPS — expanded into 1,105 rows: 1,061 per-operand assertions, plus a
   liveness row for each probe whose whole expectation is state the model
   does not carry or is a deliberate negative result, so that a probe
   rotting into ``PROBE-BAD`` is caught rather than quietly leaving the
   table.  Three properties separate it from
   every other oracle in this battery, and they are the point of it.

   **It is not derived from a decoder.**  Everything else here reads the
   same Capstone-derived metadata the tracer consumes, so a decoder
   defect is invisible to all of it: the trace is corrupted and the
   oracles agree with the corruption.  The expectations in this table
   come from sources derived from *behaviour*, never from an operand
   list.  For ``aarch64`` that is Arm's **Machine Readable Architecture**
   — the A64 ISA XML, read as execute-clause ASL, with tied destinations
   found structurally (a bank indexed by the same decode variable
   appearing on both sides of an assignment inside one execute block,
   which is what surfaces MOVK, BFM, CAS, LDG, PACIA and the SVE
   ``/M`` merging forms).  For ``riscv64`` it is the **Sail RISC-V
   model**, whose ``execute`` clauses name every architectural read and
   write explicitly, so "implicit" reduces to state the ``execute``
   clause touches that the ``encdec`` clause does not carry;
   ``riscv-opcodes`` supplies encodings only, since it carries no
   semantics.  For ``mipsel`` it is **QEMU's own TCG translators**, and
   for MIPS the translator is the only correct witness: no vendor
   machine-readable MIPS specification exists, and both candidate
   substitutes share the same error — binutils' ``mips-opc.c`` ``pinfo``
   bits and the REMS Sail MIPS model each report the destinations of
   ``movn`` / ``movz`` / ``ins`` / ``lwl`` / ``lwr`` as write-only, with
   ``mips_regfp.sail`` conceding the gap in a comment.  A table lifted
   from either would silently drop those read-after-write edges.

   **It asserts agreement rather than detecting difference.**  A
   comparison between two decoders can only see where they disagree, so
   it fails open when both move together — and they do, because a
   disassembler transcribes encodings and does not model behaviour.  The
   RVV ``v0`` mask class is exactly that case: Capstone and LLVM agree,
   and both are wrong.  No n-way decoder comparison, ``isa_crosscheck``
   included, can ever see it.  Here each row states what must be true, so
   it goes red when the boundary stops reporting it regardless of what
   any other decoder does.  That is what makes a future Capstone bump
   unable to silently drop ``x30`` from a return: the AArch64 ``ret``
   row's source is the MRA, and dropping ``x30`` turns the row red on its
   own evidence.

   **It carries dynamic weight.**  Each row records the dynamic
   instruction count its *form* reached in a traced population, so a
   reviewer ranks a finding by what it costs: SME ZA state missing scores
   0, ``mrs x0, tpidr_el0`` losing ``tpidr_el0`` scores 18.7 M.  The
   weighting is by instruction **form** — the operand text with register
   numbers and immediates wildcarded — and deliberately not by mnemonic,
   because weighting ``ldr za[w12,0],[x0]`` by every ``ldr`` in the trace
   is a gross over-estimate; the SME form and the ordinary load share
   nothing but four letters.  Matching the form keeps them apart while
   still folding across register numbers.

   ``tools/implicit_audit.py`` runs three modes over
   ``tools/implicit/<isa>.tsv``, reading the boundary through
   ``isaxcheck --batch`` (``cap_disas_raw_detail()``, with the plugin's
   ``include_implicit_regs`` policy modelled, so what is compared is what
   the dependency model would actually record).  The check runs the first
   two, both GATING, in about half a second:

   ``assert``
      Every row recorded ``OK`` must still score ``OK``.  Only the probe
      encodings are decoded — no sweep — which is what makes it
      affordable on every build rather than only on a Capstone bump.
   ``known-gap``
      Every row that is neither ``OK`` nor ``NOT-MODELLED`` carries an
      explicit disposition — ``fix``, ``modelling-decision`` or
      ``wont-fix`` — and a justification.  Dispositions are keyed by the
      whole row, ``(family, hex, kind, operand)``, and never by family,
      so a NEW member of an already-known family arrives as a row nothing
      covers and fails while the family's existing rows stay green; the
      mode proves that key property on itself, against a synthetic new
      member of each known-gap family, before checking anything.  A
      disposition standing over a gap that has since closed fails in the
      other direction, on the same reasoning that makes an ``isaxcheck``
      allowlist entry matching nothing a ``DEAD`` failure: a
      justification is a claim about something that happens.
   ``regenerate``
      Rebuilds the table against a newer MRA, Sail model or translator
      and prints the diff.  It writes ``<isa>.tsv.new`` beside the table
      and never overwrites, so the reviewer sees what moved and promotes
      it by hand; the human columns (``source``, ``disposition``,
      ``justification``) are carried forward by row key, so regenerating
      does not discard the reasoning attached to a gap that is still
      open.  Run bare it re-scores the encodings the table already
      carries, which is what a Capstone bump calls for; ``--probes``
      names a directory of ``<isa>_probes.tsv`` from a derivation that
      adds probes, and ``--weights`` a directory of ``<isa>.weights.tsv``
      (``hex`` TAB dynamic count) from a fresh traced population.

   A row's verdict is ``OK``, ``MISS-BOUNDARY`` (the spec and LLVM have
   it, the boundary does not — the two-way gate could have caught this),
   ``MISS-BOUNDARY-LLVMREJ`` (LLVM will not decode the encoding, so only
   the spec can judge), ``MISS-BOTH`` (the shared blind spot, and the
   reason the table exists), ``MISS-STRUCTURAL`` (the expectation names a
   relationship a register-name set cannot express — the implied second
   register of a CASP pair, the seven consecutive registers of an LS64
   group, the upper half of a SIMD destination — recorded rather than
   scored as either agreement or a blind spot, because it is neither),
   ``NOT-MODELLED`` (state the tracer's register model deliberately does
   not carry, so scoring it as a defect would report a modelling decision
   as a bug), or ``PROBE-BAD`` (the encoding did not decode at all).

   As it stands the table is green in both gating modes with 542 of its
   1,105 rows scoring ``OK``, and the residual sorts into three shapes.  The largest ``fix`` class is a single defect wearing three
   ISAs' clothes: **an instruction whose entire purpose is to move a
   control register moves nothing at the boundary.**  AArch64 ``mrs x0,
   tpidr_el0`` (18.7 M), ``mrs``/``msr`` of ``NZCV`` and ``FPCR``,
   RISC-V ``csrrw``/``csrrs`` of ``fcsr`` and the vector CSRs, and MIPS
   ``rdhwr $6,$29`` reading CP0 UserLocal (9.7 M) all report the register
   as text or as a bare immediate and never as a register — so every TLS
   access in an AArch64 or MIPS trace reads a value nothing appears to
   have produced.  MIPS ``mfc0`` scoring ``OK`` on the same CP0 register
   is what shows the boundary is capable of naming it.  The
   ``modelling-decision`` class is dominated by state the register model
   deliberately does not carry: cumulative FP exception status (AArch64
   ``FPSR``, RISC-V ``fflags``, MIPS ``FCSR``), which would put the whole
   FP stream on a serial read-modify-write chain through one register no
   implementation renames; the LR/SC reservation and the AArch64
   exclusive monitor, which are memory-system state a consumer models in
   its memory model; and RISC-V ``vstart`` plus the tail/mask-undisturbed
   ``vd`` read, which Sail itself records as not encoding-decidable —
   whether ``vd`` is a source depends on ``vtype.vta``, ``vtype.vma`` and
   ``vl`` versus ``VLMAX``, all written by an earlier ``vsetvl``, so a
   per-opcode template cannot decide it without carrying ``vtype`` in its
   key.  The ``wont-fix`` class is where the expectation is already
   satisfied by something coarser the model does record: the AArch64
   upper-half zeroing of a SIMD destination (25.3 M, the table's
   heaviest row) happens inside a write of the whole architectural
   register the boundary already reports.

   One family is worth reading closely because it shows what the table
   measures and what it does not.  RISC-V ``jal``, ``jalr`` and ``ret``
   in their aliased forms score ``MISS-BOUNDARY`` on the link register:
   Capstone hides ``ra`` completely, in neither the operand list nor the
   (always empty for RISC-V) implicit register arrays, and those three
   rows carry the three heaviest weights in the RISC-V table — 500 M,
   448 M, 128 M.  The trace is nonetheless correct, because the plugin
   restores the link register *above* this boundary, in
   ``refine_alias_fields()`` (``champsim_tracer_decode.cc``), which adds
   ``REG_LR`` as a destination to a call that decoded with none and as a
   source to a return that decoded with none.  A decoded ``ret`` in a
   real trace reads ``%lr``.  The rows are carried as
   ``modelling-decision`` with that reasoning attached, and they are the
   standing reminder that this table's subject is the decode boundary,
   not the whole decode path.
``features.smc``
   Self-modifying code: revision minting, content-signature id
   reuse, and the per-pc revision cap, across four ISAs and nine SMC
   families.  Four rewrite a block without disturbing its instruction
   boundaries (``patch_once`` / ``flip_flop`` / ``cap_overflow`` /
   ``write_no_exec``); four are **shape-changing** — ``grow`` and
   ``shrink`` re-emit the block with one instruction more or fewer,
   ``boundary_shift`` re-cuts the same code bytes into different
   instructions (``x86_64`` and ``riscv64``, the variable-width ISAs),
   and ``grow_return`` runs A → B → A across a shape change to prove
   the returning state reuses its original ``template_id``.
   ``rewrite_identical`` is the negative control: identical bytes
   rewritten and re-executed four times must mint nothing.  Every
   family asserts an exact revision count, that each retained revision
   is byte-correct for a written state, and that the body's ``ENTRY``
   records name the revision that was live at each position.  A
   host-side truth table over ``champsim_tracer_smc_match.h`` drives
   the discriminator directly, covering the extent-only branch
   (byte-identical overlap, different extent — must not mint) that no
   guest workload can reach.
``features.mips_fragment_split_absence``
   Pins the current fact behind ``split_tb_into_fragments``'s mid-TB
   continuation path (the splitter branch that seals a fragment at a
   branch-classified insn that is NOT the owning TB's last insn, then
   keeps walking): on MIPS there is currently no instruction that
   exercises it.  The MIPS T-family conditional trap
   (``teq``/``tne``/``tlt``/``tltu``/``tge``/``tgeu`` and the
   immediate forms) was the only one — ``gen_trap`` in
   ``target/mips/tcg/translate.c`` emits a conditional TCG branch to a
   helper and leaves translation running straight on, so QEMU
   literally keeps decoding past an insn the tracer classified as a
   branch — until ``5bf597d751`` correctly reclassified the family as
   ``GEN_OP_CMP``/``BRANCH_NONE`` (a compare that may except, the same
   shape x86 ``BOUND`` has; see ``features.reg_snap_accounting``
   above for the 188,726-block cost of the old misclassification on
   the ``mcf_user_mipsel`` sample).  That fix also removed MIPS's only
   exercise of this splitter path — ``BRANCH_REP`` still covers it
   elsewhere, on x86 (``X86RepIterationFanout``, ``rep movsq`` mid-TB;
   see ``features.string_memops`` above) and on aarch64, whose
   FEAT_MOPS bulk copy/set triple QEMU translates straight through
   inside one TB (see ``features.mops_memops``).  Rather than leave the
   MIPS absence undocumented, this check decodes a ``--coverage``
   mipsel trace (chains in every registered ``coverage_probe`` block,
   including ``MipsInlineConditionalTrap`` — the regression test for
   the misclassification itself) and asserts that no template's
   instruction list carries a branch-classified insn anywhere before
   its last two positions (last = a bare terminus; second-to-last = a
   branch immediately followed by its one architectural delay-slot
   insn).  A future classification change that gives some MIPS
   instruction the T-family's shape again will surface as an earlier
   occurrence, and this check fails until a dedicated
   ``coverage_probe`` (mirroring ``X86RepIterationFanout`` /
   ``MipsInlineConditionalTrap``) exists to prove the splitter folds
   it correctly.

.. _validator-mutation:

Mutation testing (``mutation``)
--------------------------------

The rest of the validator asks *does a correct trace pass?*.
``mutation`` asks the dual, more important question: *does an
incorrect trace fail — and does the right check catch it?*  It builds
one known-good substrate trace, then applies a catalogue of
deliberate corruptions one at a time and asserts a specific check
reacts to each.  A corruption nothing catches is a **HOLE** — a place
the suite would silently accept a wrong trace — and the command exits
non-zero if any applied mutation is not caught.

.. code-block:: console

   $ python3 -m champsim_tracer_validator mutation \
         --build-dir ../../../../build \
         -o out/mutation --json out/mutation/matrix.json

Four mutation layers, matching where strictness has to live:

``oracle``
   The mutation is applied to the already-decoded ``(trace_meta,
   templates, entries)`` triple, and the full ``validator.validate``
   oracle is re-run against the damaged decode through a
   decoder-shaped stand-in (no re-tracing needed); it must raise a
   gating error in one of the mutation's declared ``expect`` checks.
   20 of the 30 catalogue entries are this layer: flipping a captured
   dst-register value or misattributing it to the wrong register id,
   swapping two memop addresses or flipping a captured load/store data
   byte, dropping the memops from the segment's final body entry (the
   D4 mechanism itself — a no-op on the shared diamond substrate, whose
   window always closes on the exit syscall, so strictness is proven
   end-to-end by ``features.final_entry_memops`` instead) alongside its
   general form, dropping the memops from one non-final,
   otherwise-invariant execution of whichever template repeats the
   most (``mid_entry_memops_dropped`` — the ``memop_bimodality`` check's
   teeth, proving it catches the D4 *shape* anywhere in the stream, not
   only a positional last-entry special case), relabeling a pinned
   instruction's opcode class or branch classification, flipping a raw
   instruction byte in a template, truncating / reordering the first
   two blocks of a predicted wrong-path chain, a depth-0 WP
   missequence paired with a later synthetic fault mark (the fault
   must not excuse the earlier divergence), reordering two
   correct-path entries, splitting one whole-block entry into its two
   §4.2a stretches and emitting the continuation before its own
   prefix (``split_pair_reorder`` — ``range_continuity``'s teeth),
   forging a foreign guest-thread id onto an
   entry, corrupting a per-memop physical-page value, dropping a
   ``DEVIO_STOP`` record, corrupting a self-modified block's
   non-baseline revision bytes, and corrupting a *shape-changed*
   revision's bytes (a revision minted at a different instruction
   count than the block's original template — the class only
   shape-agnostic minting produces).  The DEVIO and SMC mutations
   run against dedicated purpose-built substrates rather than the
   shared diamond-CFG one, since the diamond CFG carries neither disk
   I/O nor self-modification; the two SMC mutations use different
   substrates (``flip_flop`` and ``grow``).
``wire``
   The mutation is applied to the raw ``.cst`` container bytes (ustar
   member payloads), and the real ``cst_decode`` binary runs against
   the damaged file — it must reject the file outright (non-zero
   exit).  This proves the decoder itself rejects structurally
   malformed input rather than silently emitting a partial trace. 3
   catalogue entries: corrupting the ``CST_MAGIC`` in the header
   member, removing the body member from the container, and
   truncating the body member payload.  The block-record injections
   below also end at the decoder, but they need a raw-dump locate
   pass first, so they ride the ``wire_oracle`` plumbing.
``wire_verify``
   A wire-level mutation that leaves the body stream structurally
   well-formed and corrupts only what a record *means*, so no decode
   can reject it — the catch has to come from the check that owns that
   meaning.  The mutated file is handed to ``cst_decode --strict
   --verify-branch``, which must reject it.  1 catalogue entry:
   ``branch_target_corrupt`` moves one encoded branch target by
   flipping the low bit of its ``CST_FID_BRANCH_TARGET`` displacement
   delta — the negative control for the branch-outcome self-check,
   including its control-flow-diversion accounting, which must keep
   flagging a moved target rather than filing it under a diversion.
``wire_oracle``
   A wire-level mutation whose catch is not guaranteed to be an
   explicit decoder bounds/tag check — the corruption may desync the
   body stream in a way ``cst_decode`` tolerates rather than rejects.
   The real decoder runs first; if it accepts the file (rc=0), the
   mutated file is handed to the full ``validate()`` oracle as a
   second line of defense, and a semantic mismatch there is an
   equally valid catch.  6 catalogue entries, all epoch-0x1E
   block-record injections: a field-delta record is spliced into one
   entry's own ``cp_delta_section`` at ``BLOCK_POS`` (the section's
   ``len`` and ``n_records`` ULEBs re-encoded; the target aimed by a
   ``--format=raw`` locate pass over the pristine substrate).  Four
   MUST die in the decoder — ``range_stop_overflow`` (``BB_STOP``
   past ``num_insns``), ``range_inverted`` (``BB_START`` at
   ``num_insns`` against the default stop), ``range_out_of_record``
   (a shrunken stop orphaning a per-insn record the entry itself
   stages), and ``fabricated_branch_on_unresolved``
   (``CST_BB_FLAG_BRANCH_UNRESOLVED`` raised in the same section
   that stages a branch outcome — the §5.6 prohibition made bytes).
   Two are decoder-clean by construction and MUST be caught by the
   validator's range oracles — ``range_stuck`` (a quiet entry's stop
   shrunk: the invocation is left open mid-stream with no excursion,
   and the cell delta-persists to every later entry;
   ``range_continuity``) and ``stuck_bb_flags`` (the unresolved flag
   latched onto a WP-forking entry whose outcome rides the
   persistent cells; ``wp_fork_resolved``).  These six re-cover, and
   extend, the desync class the retired ``CST_WP_CHAIN_HAS_EVENTS``
   presence-bit flips proved before the events section left the
   wire.

Each catalogue entry records, per mutation, whether it was applied,
caught (and by which check id), or skipped (the substrate did not
carry the feature the mutation targets — e.g. no DEVIO records on a
non-devio substrate) — the *mutation matrix*.  The substrate itself
must validate clean before any mutation is applied
(``baseline_clean``), or every subsequent "catch" would be a false
positive from a substrate that was already broken.

Arguments: ``--build-dir``, ``-o``/``--work-root`` (default
``/mnt/md0/QEMU/cst_runs/strictaudit/mutation``), ``--seed``, and
``--json`` (also write the matrix to this path).

``full``'s ``features.mutation_strictness`` check calls the same
``run_mutations()`` machinery in-process rather than shelling out to
this sub-command.

What gets checked
-----------------

Every ``validate`` invocation runs a fixed suite of named checks
against the decoded trace.  Errors are blocking; warnings are
non-blocking; info-level entries summarise what passed.  The summary
output groups by check name with severity counts and prints the first
five errors verbatim.

Structural / format invariants
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These don't need a generator ``meta.json`` and run on any ``.cst``.

``encoding_map_completeness``
   Every ``reg`` / ``opcode`` / ``branch_type`` id that appears in a
   template has a name entry in the matching encoding map.  Also
   detects writer-side fallback names (``REG_<n>`` /
   ``OP_<n>`` / ``FID_0x...`` / ``UNKNOWN_<n>``) that imply the
   encoder fell out of its own name tables.

``header_window``
   ``start_insn`` / ``warmup_insns`` / ``total_target_insns`` in the
   header match the ``--start`` / ``--warmup`` / ``--stop`` the trace
   was invoked with.  Relaxed when ``--start-symbol`` is set (the
   exact icount the symbol resolves to is not predictable; only that
   ``start_insn > 0`` is required).

``iframe_cadence``
   The trace's ``iframe_count`` matches the per-template hit
   distribution rolled against the configured ``iframe_rate``:
   ``sum(per_template_hits // rate)``.  Each individual IFRAME's
   contents (CP dyn_params, reg_snaps, metaflags, full WP chain,
   WP events) is already verified byte-for-byte by ``cst_decode``'s
   ``validate_iframe()`` at decode time — a failure there surfaces
   as a decode-stage exception before this check runs.

``regfile_records``
   Exactly one BODY_TAG_REGFILE per ``(segment, thread)``.

``thread_switch``
   Every segment body opens with one mandatory
   BODY_TAG_THREAD_SWITCH naming the starting thread, so
   single-thread runs must show exactly that opener (count equal to
   the REGFILE cadence) and no interleaving switches; multi-thread
   runs must show at least one switch per expected thread (otherwise
   no interleaving was captured).

``thread_distribution``
   Every expected thread contributed entries; no entries reference a
   ``thread_id`` outside ``[0, expected_threads)``.  Because
   ``thread_id`` is the guest-thread identity (dense 0..N-1 by
   first-sighting, not the vCPU index), this bound holds on system-mode
   marker runs too: a single-threaded pinned process is exactly
   ``thread_id`` 0 however many vCPUs it migrated across, and the clone
   test's pair is exactly ``{0, 1}`` — a stray higher id would be a
   foreign thread leaking past the pin.

``thread_records``
   Positional per-record thread bookkeeping, from the decoder's body
   record stream: an ENTRY carries the switch flag exactly when its
   ``thread_id`` differs from the previous ENTRY's (plus the
   mandatory opener on the segment's first ENTRY), and each
   contributing thread has exactly one REGFILE record positioned
   before its first ENTRY — the delta decoder's hard prerequisite.

``thread_chain``
   User-flow continuity of the interleaved body stream, matched **per
   guest thread**.  Because ``thread_id`` is the guest-thread identity
   (one tid across vCPU migration), the entries of a single tid,
   filtered from the interleaved stream, are that one thread's user
   execution in order — so each must continue that SAME thread's
   control flow: its start PC is reachable from the tid's previous user
   block (fall-through, static branch target, or a CP-observed profile
   target).  A partial user entry (a declared range stopping short of
   the template, :doc:`format` §4.2a) never reached its terminating
   branch, so its only legitimate user-side successor is its own
   continuation: the SAME template resuming at exactly its stop index —
   asserted even across an intervening kernel excursion, which is
   precisely what the range makes checkable.  A kernel excursion may
   otherwise resume the thread at a redirected PC (a handler that never
   returns), so after one a fresh entry restarts the chain without
   penalty.  A disconnect within a tid's own chain is an *orphan*: a
   dropped user block, a phantom entry, or foreign code leaking past
   the pin.  Matching per tid (not globally against a live set) cannot
   launder one thread's block onto another's successors, so it is
   strictly stronger than the pre-identity check; ``chains`` in the
   info detail is the number of distinct guest threads that contributed
   user entries.  Runs in ``validate_structural`` (``thread_test``,
   ``churn_test``) and in every ``validate()`` call — i.e. the ``all``
   battery.

``thread_strand``
   Sequentiality of every ``(thread_id, asid)`` context — the property a
   consumer relies on when it keys per-thread state on that pair and
   reads the entries under one key as a single instruction stream.
   Where ``thread_chain`` follows *user* code per thread, this check
   walks the whole stream, kernel included, and uses each entry's
   resolved terminal branch: filtered to one context, entry N's branch
   target should name entry N+1's resume PC — the template's start, or
   ``insns[bb_start].pc`` for a continuation entry (:doc:`format`
   §4.2a); one explicit PC, never a set of alternatives.  When it does
   not, the strand was diverted, and
   the dangling target is remembered.  Every diversion the format
   documents crosses a boundary the wire makes visible — entering an
   excursion raises ``fault_depth``, returning lowers it, a
   privilege-domain gap changes ``is_system``.  A diversion at the SAME
   depth and privilege whose target is picked up *later*, while the
   entries in between chained happily among themselves, is none of
   those: it is two independent instruction streams braided into one
   context, which is what a shared ``thread_id`` looks like from outside.
   Braided resumptions are errors; diversions that never resume are not
   (a strand that simply ends, or an excursion outside the trace's
   coverage, leaves a dangling target with no braid — the
   ``cst_decode --verify-branch`` census is the tool for those).  This is
   the check that fails a trace in which two vCPUs' kernel work shares
   one thread id.  Runs in ``validate_structural`` and ``validate``.

``range_continuity``
   Executed-range well-formedness and continuity (:doc:`format`
   §4.2a).  Every entry's declared range must satisfy
   ``0 <= start < stop <= num_insns``; a continuation entry
   (``bb_start = k > 0``) must continue an OPEN invocation of the same
   template in the same ``(thread_id, asid)`` context whose stop is
   exactly ``k`` — a continuation without its prefix, or a
   non-contiguous one, is a wire defect, never a licensed shorthand.
   While an invocation is open, the only entries its context may emit
   before the continuation are the excursion's (strictly deeper
   ``fault_depth``); a same-or-shallower entry that is not the
   continuation abandons the block, which is legal only when an
   excursion is on the wire to explain the redirect (a handler may
   never return) — a user-mode stream cannot lose the tail of a block
   invisibly.  Under ``faults=0`` the handler is excluded from capture,
   so the abandonment arm is N/A there; continuity always holds.  A
   trailing open invocation (window or budget close mid-block) is
   legal.  Runs in ``validate_structural`` and ``validate``.

``wp_fork_resolved``
   A wrong path forks off a RESOLVED terminating branch (the fork
   redirects the PC to the not-taken alternative of an outcome the
   tracer observed), and an entry whose range does not reach its
   branch forks no wrong path.  An entry that carries a wrong-path
   chain but no resolved branch outcome is therefore
   self-contradictory — a stuck ``CST_BB_FLAG_BRANCH_UNRESOLVED``
   latching past the entry it described, or a forged chain.  Runs in
   ``validate_structural`` and ``validate``.

``thread_end``
   ``CST_BB_FLAG_THREAD_END`` marks each ``(thread_id, asid)``
   context's final entry, at every close route — thread exit, END
   marker, icount/simpoint budget, idle ceiling, machine shutdown
   (:doc:`format` §4.2a/§5.6).  A consumer learns a context is over
   from the flag, never by inferring it from the context not
   reappearing.  The check asserts the wire-observable contract in
   both directions: the entries the close emits as each context's
   final — the stream's trailing run of context-final entries — must
   all carry the flag, whichever route closed the window; and an
   entry carrying the flag anywhere must be its context's last.  A
   context that merely scheduled away mid-window is exempt from the
   first direction (its final entry predates the close and the frozen
   wire cannot stamp it retroactively; the thread-switch record
   explains the departure).  Its falsifiers run in
   ``range_cells --selftest`` (fixture level, always) and in the
   mutation battery (``thread_end_dropped``, trace level).  Runs in
   ``validate_structural`` and ``validate``.

``syscall_fault_nesting``
   Nested-excursion discipline (system-mode marker runs).  The
   generated marker workload issues one syscall whose kernel path is
   guaranteed to fault — ``sysinfo`` writing into a never-touched
   demand-zero page (``emit_trace_fault_probe``; the buffer sits
   64 KiB past the .data tail so no guest page size up to 64 KiB
   pre-maps it) — so the trace must contain at least one user-syscall
   excursion with ``fault_depth >= 1`` entries inside it.
   Independent of the probe: per-tid fault depth changes by at most
   one between consecutive entries, and a continuation entry
   (``bb_start > 0``) sits directly at its excursion's boundary — the
   tid's previous entry either ran strictly deeper (the handler the
   continuation returns from) or is the block's own prefix stopped at
   exactly the resume index (``faults=0``, where the handler is
   excluded and the stretches arrive adjacent).  Checkable by
   adjacency because program order is unconditional (:doc:`format`
   §4.2a).  The fault-depth histogram is reported for regression
   visibility.

``user_code_identity``
   ASID-pin content gate (system-mode marker runs).  Every
   user-privilege template the CP stream executed must byte-match the
   pinned binary's ELF image at its instruction addresses — a foreign
   process scheduled into a reused ASID cannot byte-match the
   ``-nostdlib`` workload even where guest processes share load
   addresses.  WP-only user templates are exempt (wrong-path fetch
   may wander) and counted in the info summary.

``wp_events``
   The writer's aggregate ``fault_count`` and
   ``translation_unavail_count`` match a per-entry walk of each
   ENTRY's ``wp_entries`` payloads.

``atomic_count``
   The writer's aggregate ``atomic_count`` matches a static walk
   of every CP+WP entry's per-insn ``is_atomic`` field, scoped to
   each entry's declared executed range (:doc:`format` §4.2a): the
   tally counts observations, so a fault-split prefix that stops
   before an atomic contributes nothing for it (the continuation
   carries it exactly once) and a budget-cut WP last block never
   counts the atomics past its cut.

``profile_consistency``
   Cross-validates the run-aggregated template profile block
   (:doc:`format` §6) against the decoded body — overlapping
   coverage that exercises the profiling machinery independently of
   the behavioural metadata checks.  Asserts: ``exec_cp`` /
   ``exec_wp`` coverage agrees with which template IDs actually
   appear as CP entries / WP-chain BBs; ``sum(exec_wp)`` equals the
   total WP BBs in the body, and ``sum(exec_cp)`` equals the CP
   entry count when no IFRAMEs are present; for a non-indirect
   branch BB the single target's ``taken_cp + nottaken_cp`` is
   ``exec_cp`` (or ``exec_cp - 1`` — the one trailing execution
   whose successor the trace window never observed; anything else
   is mis-attribution or wrong-path contamination); and a per-insn
   mem-op count implies the matching path executed.

CP execution invariants
~~~~~~~~~~~~~~~~~~~~~~~

These require the generator's ``meta.json`` and use ``correct_path``
to anchor expectations.

``blocks_covered``
   Every block on ``correct_path`` appears in the trace's CP block
   sequence at least once.

``cp_execution_order``
   The collapsed CP block sequence is a prefix of ``correct_path``
   (no out-of-order CP entries).

``template_raw_bytes``
   Every template's ``raw_bytes`` round-trip-disassembles to the
   source asm bytes for that block's PC range.

``block_insn_counts``
   Each template's instruction count matches ``meta``'s expected
   count for the blocks it covers.

``block_assertions``
   Per-block static assertions (sync flags, branch outcomes,
   asserted opcodes) hold.

``expected_insns``
   Author-declared per-instruction exact-check vectors
   (``BlockPlan.expected_insns``) match the decoded trace.  Each
   declared field is optional and checked only when present: per-insn
   ``src`` / ``dst`` register names, ``opcode``, ``branch_type``,
   ``insn_flags`` (and ``insn_flags_clear``), the per-output dependency
   lists (``dst_deps`` / ``load_addr_deps`` / ``store_addr_deps`` /
   ``store_data_deps``), and the per-operand lane-mask bitmaps.
   Reports author-intent-vs-trace divergence; emits an info-level
   "skipped" entry when no block declares ``expected_insns``.

``cp_memops``
   Every block's expected memop multiset (``kind``,
   ``arena_u64_index``, ``data``) is observed in the trace,
   including ``data`` values for ``memdata=1`` runs.  The
   representative is an execution *group*, never a single entry: one
   dynamic execution can arrive as several ranged entries
   (:doc:`format` §4.2a) — the ``[0, k)`` prefix carries the memops
   it observed, the ``[k, n)`` continuation the rest — so the check
   joins the first execution whose stretches tile ``[0, n)`` and
   compares the joined ``dyn_params``.  When no complete execution
   exists (a close cut the only invocation mid-block), the expected
   multiset is scoped to the instructions the declared ranges
   observed: an unobserved tail is not a missing memop, the wire says
   it was cut.

``memop_insn_attribution``
   Every observed ``dyn_param`` is attributed to an insn whose
   template declares the matching access kind.

``memop_count_assertions``
   Per-block expected memop counts (load/store) hold.

``addr_recompute``
   Every load/store address is independently recomputed from the
   trace's reg snaps + Capstone's per-operand addressing-mode
   decode, and the result matches the trace's recorded address.
   This is the strongest address-correctness check — works for
   complex SIB / base+index*scale forms and per-ISA addressing
   modes.

Register identity
~~~~~~~~~~~~~~~~~

``static_reg_sets``
   Every template's ``src_regs`` / ``dst_regs`` match Capstone's
   operand-decode of the same bytes.  Comparison is by symbolic
   name resolved through the trace's own ``reg`` encoding map (not
   by numeric id — so layout shifts in GenericRegId don't false-fail).

``expected_reg_sets``
   Per-insn author-declared register sets (when a block specifies
   them) match what Capstone says about the asm we actually wrote.

``reg_value_assertions``
   Specific reg-value assertions a block declares for its
   end-state regs hold.

Regdata semantics (when ``--regdata`` is in effect)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``metaflags``
   For each flag-writing arithmetic insn (ADD/SUB/AND/OR/XOR/CMP/
   TEST), recomputes the canonical Z / N / P bits from the dst-GPR
   snap and asserts they match the FID_METAFLAGS byte the writer
   emitted.  C / V depend on operand history we don't always have,
   so the check excludes them.

``regdata_reconstruction``
   For ADD / SUB / AND / OR / XOR with two GPR sources, simulates
   ``op(reg_state[src_a], reg_state[src_b])`` and asserts the trace's
   dst snap matches.  Tracks per-(thread, reg) state across CP entries
   so the chain composes.  2-op SUB (x86 AT&T ``sub src, dst``) is
   detected and the minuend / subtrahend reordered before compute.
   Atomic RMW (lock xadd / ldadd / amoadd / ll-sc) is skipped because
   the dst is loaded from memory rather than computed from srcs.

``lane_masks``
   Per vec-classified instance, validates the four lane-mask
   families against the lane model: every load/store-data mask is
   contained within the register-lane span it feeds/drains; for
   lane-parallel insns every dst lane is reachable from a src or a
   feeding load; reducer / scalar-bridge ops narrow; and the
   max-popcount across an insn's masks never exceeds the register
   lane count derived from the Capstone ground-truth disassembly
   (a narrower mask is correct for insert/extract/reductions, only
   an over-span is flagged).  Vacuous on scalar-only traces.

Coverage / WP
~~~~~~~~~~~~~

``opcode_coverage`` / ``branch_coverage`` / ``reg_coverage``
   Info-level summaries comparing observed-in-trace vs
   reachable-on-this-ISA universes.  Helpful when a new generic
   opcode lands and you want to know whether the asm-block library
   exercises it yet.

``dep_refine_coverage``
   Info-level summary tallying each instance into a dep-refiner
   bucket inferred from its emitted dep-mask shape
   (``DEP_PASSTHROUGH`` / ``DEP_LEA`` / ``DEP_X86_STACK_PUSH`` /
   ``DEP_X86_STACK_POP`` / ``DEP_ALL_TO_ALL`` / ``DEP_DEFAULT`` /
   ``DEP_OTHER``).  Errors only if a probe's declared
   ``dep_refines`` bucket never appears in the trace.

``wrong_path_chains``
   Every CP-side branch with a predicted ``wp_chain`` in
   ``meta.wrong_paths`` matches the trace's actual WP block
   sequence (as a prefix, trimmed to the
   ``wpdepth`` instruction budget).  Threads a
   ``cp_pos_offset`` through when ``--start-symbol`` trimmed the
   prologue so the per-CP-position lookups index against the
   original CFG.  A chain SHORTER than its prediction is accepted only
   at a real terminator — the depth budget, a privilege-domain crossing,
   a translation-unavailable boundary, or a whole-path ``wpprune`` —
   every one of which is a *fetch* condition.  A syscall is not one of
   them: the wrong path continues past a syscall at its fall-through, so
   a chain that stops at one is a truncation like any other.

``indirect_wp_assertion``
   Validates the specific ``indirect_wp_one_target`` /
   ``indirect_wp_multi_target`` probe blocks' expected WP-target
   patterns.

``plugin_cp_tail_dropped``
   Diagnostic: surfaces the (known) plugin behaviour of dropping
   the CP entry for the final TB when it ends in a process-exiting
   syscall, so downstream checks don't false-fail on the missing
   tail block.

``unconditional_direction``
   Every unconditional direct jump / direct call records its branch
   outcome as *taken* — an unconditional branch can never fall
   through.  A trace-wide guard on the ``CST_FID_BRANCH_TAKEN``
   direction FID and the branch-type taxonomy that laundered-away
   profile counts would otherwise hide.

``call_return_balance``
   Dynamic call and return counts stay in the same ballpark across the
   trace, catching a systematic call-vs-return misclassification of the
   branch-type map.

Alongside these, the suite runs several checks that need no separate
prose here: ``data_widths`` (the per-slot ``CST_FID_LOAD_SIZE`` /
``STORE_SIZE`` / ``DST_REG_WIDTH`` family holds the recorded access /
write width), ``per_execution_memop_data`` and
``per_execution_memop_shape`` (the k-th execution carries the k-th
expected memop sub-list, and the per-insn (loads, stores) shape is
stable across executions), and — in system-mode runs —
``syscall_transitions`` and ``fault_excursions`` (user→kernel→return
privilege transitions off the ``SYSTEM`` bit, and the fault-depth
invariants).  ``syscall_transitions`` is range-aware: a syscall is
armed as pending only when the entry's declared range includes the
template's final (syscall) instruction — a stretch a demand fault cut
before the syscall must not arm — and every position it compares is
the range-resolved PC (``insns[bb_start]``), never the template's
``start_pc``.  The ``devio`` and ``physaddr`` record families have their
own dedicated structural assertions too, but as ``features`` tier
checks (``features.devio`` / ``features.devio_attrib`` /
``features.physaddr``) run through the unified ``full`` runner rather
than a plain ``validate`` invocation — see
:ref:`Unified runner <validator-full>` above.

.. _validator-segmentation:

Segmentation test (``simpoint_test``)
-------------------------------------

This test validates that the plugin's *simpoint* mode produces
self-contained ``.cst`` segments.  Each per-simpoint output file
must decode independently: its header re-emits all encoding maps,
its templates section is self-sufficient, its body starts with a
BODY_TAG_REGFILE record, and the decoder reaches the trailer without
borrowing any state from any other segment.

.. code-block:: console

   $ python3 -m champsim_tracer_validator simpoint_test \
         --seed 0x0102 -o out/ --isa x86_64 \
         --build-dir ../../../../build --hot-iters 5000 --regdata

What it does:

#. Generates a synthetic program with a long-running loop
   (``--hot-iters`` defaults to 5000 so the program runs past the
   second simpoint interval).
#. Writes a simpoint-selection file picking two intervals (interval
   id 0 and interval id 2).
#. Runs ``trace_window=simpoint:file=...+interval=N+simulation=M``
   under the plugin.  The plugin writes each segment to its own
   file named ``<prog>_<isa>-<positionB>.cst``, where
   ``<positionB>`` is the simpoint position in billions of
   instructions (e.g. ``mcf_x86_64-0B.cst``,
   ``mcf_x86_64-0_000025B.cst``); the validator collects them with a
   ``<prog>_<isa>-*.cst`` glob.
#. Asserts the per-segment coverage from the captured console: every
   ``finished segment`` line — one per scheduled cluster, not just the
   first — must read ``clock_minus_wire=0`` and close ``OK`` at its
   budget.  This is the same comparator the system cells run, applied
   to a *multi-segment* console; a mid-stream reopen whose accounting
   drifts (the open-boundary crossing block is published whole while
   the raw clock bills the segment from the window start) fails the
   cell here rather than riding through on the segment files alone.
   A console with no parsable line is a failure, never a skip.
#. Validates each segment file *in reverse order* — explicitly
   touches segment 1 before segment 0 — to prove segment N is
   fully self-decodable without any prior knowledge of segment N-1.

The validation is structural (no ``correct_path`` cross-check —
simpoints intentionally start mid-program where the CFG anchor
isn't available).  Asserted invariants:

* every segment close line reads ``clock_minus_wire=0`` and ``OK``,
* segment is internally consistent (encoding-map completeness,
  iframe-cadence, atomic_count / wp_events writer-vs-walk),
* exactly one REGFILE record (single-thread),
* zero THREAD_SWITCH records,
* every template/encoding id observed has a non-fallback name.

.. _validator-multi-thread:

Multi-thread test (``thread_test``)
-----------------------------------

This test verifies that the plugin correctly handles multi-vCPU
traces: distinct REGFILE records, BODY_TAG_THREAD_SWITCH records on
interleaving, and per-thread state separation.

.. code-block:: console

   $ python3 -m champsim_tracer_validator thread_test \
         --isa x86_64 -o out/ \
         --build-dir ../../../../build --regdata

What it does:

#. Assembles a hand-written 2-thread asm template from
   ``_thread_test_asm.py`` (per-ISA, no diamond CFG involved).  The
   parent spawns one child via the kernel's ``clone`` syscall with
   ``CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES |
   CLONE_FS | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID``; both threads
   run identical 1000-iteration atomic-RMW loops on a shared word;
   parent spins on the kernel-cleared ``child_tid`` slot (no
   ``futex`` syscall required), then ``exit_group``.
#. Traces the program under qemu-user with the plugin loaded.
#. Validates with ``expected_threads=2``.  Asserts:

   * **regfile_count == 2** (one REGFILE per thread),
   * **thread_switch_count > 0** (threads interleaved at least once),
   * **thread_distribution**: both ``thread_id=0`` and ``thread_id=1``
     contributed CP entries; no entry references an out-of-range id,
   * **atomic_count** picks up every atomic-RMW instruction (lock
     xadd / ldadd / amoadd / ll-sc, per ISA) via ``is_atomic``.

Run-to-completion is reliable because the parent's
``exit_group`` only fires after the child has set ``child_tid`` to
zero on exit — both threads always finish.  Per-thread entry counts
are deterministic enough to compare across runs at a glance.

System-mode SMP form
~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ python3 -m champsim_tracer_validator thread_test \
         --system --smp 2 --isa mipsel -o out/ \
         --build-dir ../../../../build --stop 2000000 --iters 2000000

``thread_test_asm(isa, marker=True, iters=N)`` renders the same clone
pair with the trace marker at ``_start`` (pinning the window before
the clone — both guest threads share the pinned address space) and
the end marker before ``exit_group``.  In system mode the pair is
given DISTINCT per-thread pointers (the parent installs one before
the marker; the child receives one via ``CLONE_SETTLS``) and a start
barrier holds the parent until the child has entered user code, so the
window reliably captures both — the tracer then resolves them to two
GUEST-THREAD tids (``0`` for the parent, ``1`` for the child), **not**
vCPU indexes.  So:

* the record-cadence checks (``thread_records``, ``regfile_records``,
  ``thread_switch``) and ``thread_distribution`` run against the
  guest-thread population — exactly ``{0, 1}``, independent of ``-smp``,
* ``thread_chain`` decomposes the user entries into the two guest
  threads' control-flow chains **per tid** — one well-formed chain each,
  which a migrating thread keeps intact because it holds one tid across
  vCPUs,
* ``thread_strand`` extends that to kernel code: with two vCPUs both
  running kernel work for the pinned process, each ``(thread_id, asid)``
  context must still read as one sequential strand, which is only true
  if the two vCPUs' strands carry different thread ids, and
* the captured console log's segment-close line must not report an
  under-budget close.

``--migrate`` turns it into an SMP migration stress: it adds a periodic
``sched_yield`` to every ISA's RMW loop and drops the mipsel CPU-0
affinity confinement, so under ``-smp N`` the guest scheduler spreads,
time-slices, and migrates the pair.  ``--seeds K`` repeats the traced
run ``K`` times under varied scheduling entropy and reports ``x/K``
passing; with ``CST_TIDDIAG`` the plugin logs the ``vcpu <-> tid``
bindings it observed to stderr, and the harness asserts the run set
**witnessed the tid decoupled from the vCPU** at least once — a tid
seen on two vCPUs (migration), a vCPU hosting two tids (time-slice), or
a binding whose tid simply differs from its vCPU index.  A run whose
bindings were all ``tid == vcpu`` is ambiguous, not a failure; the gate
fails only if *no* run in the set distinguished the identity.

.. _validator-churn:

Multi-process churn test (``churn_test``)
-----------------------------------------

The ASID pin must follow *only* the marked process across ASID reuse.
On MIPS the ASID space is 8 bits, so a few hundred short-lived
processes force a generation rollover and the guest kernel reassigns
the pinned ASID value to foreign processes while the trace window is
open — the exact scenario the pin's reuse detector
(``pin_asid_reuse_suspected``) and the kexc ownership model guard.

.. code-block:: console

   $ python3 -m champsim_tracer_validator churn_test \
         --seed 0x5150 --isa mipsel -o out/ \
         --build-dir ../../../../build

What it does:

#. Generates the standard marker workload with two extra probes: the
   fault probe (as in every marker run) and a ``nanosleep`` probe
   (``--sleep-probe``, default 40 s) right after the pin — the sleep
   holds the window open on a frozen user clock while init churns.
#. Stages an initramfs whose init forks ``--churn-pre`` (default 60)
   short-lived processes before starting the workload and
   ``--churn-during`` (default 300) more while it runs; each shell
   iteration forks a subshell and execs ``/bin/true``, two fresh mm's
   (and so two fresh ASIDs) per iteration.
#. After the guest run, asserts on the decoded trace:

   * **user_code_identity**: every CP-executed user template
     byte-matches the marked binary's ELF image,
   * **thread_chain**: the user entries form one control-flow chain,
   * the window closed **at budget** on the user clock
     (``user_covered == budget``, OK flag) — the workload outlives
     the budget by construction (``--hot-iters``),
   * ``pin_asid_reuse_suspected`` and ``kexc ASID-write events`` are
     reported from the stats log (the detector may legitimately fire;
     the content checks above are the gate),
   * ``cst_audit`` and ``cst_decode --strict`` exit clean.

.. _validator-lldet:

The lldet watchdog (calibrated timeouts + condition sampling)
-------------------------------------------------------------

Every qemu invocation the validator makes — the ``trace`` subcommand in
both modes, ``thread_test``, ``churn_test`` and ``simpoint_test`` — runs
under an external watchdog, ``_lldet.py``.  It is harness-side machinery
only: the tracer itself never detects deadlock or livelock (it blocks
honestly when, for example, its compress sink stalls), and the watchdog
never touches the tracer or QEMU.  The design follows the maintainer's
ruling on automated livelock detection: set reasonable timeouts derived
from the number of instructions being traced, using non-livelocking
traces as the estimator.

**Calibrated deadline.**  A cell's instruction budget is known up front
(``--stop``, or the marker window's user-instruction budget).  The
watchdog computes ``timeout = k * (boot_floor + budget / ips)`` where
``ips`` is the *measured* healthy throughput of that
``isa/mode/smpN/wp`` configuration, read from the checked-in table
``champsim_tracer_validator/lldet_calibration.json``.  The table carries
its provenance (date, HEAD sha, host, seeds, the exact command) beside
the numbers; per config it stores the *slowest* healthy sample, the
most generous choice.  ``k`` (5.0) is stated in the table.  A cell with
no stated budget — a run that traces to workload exit, like
``thread_test`` or a simpoint schedule — falls back to a per-mode
ceiling instead.  Two footnotes on the configuration axes: a ``nowp``
row cannot be measured because ``wpdepth > 0`` is a plugin invariant
(lookups for it fall back to the slower ``wp`` sibling), and the table
is calibrated at the standard depth 64 — an extreme-depth stress cell
(``wpdepth=65536``) runs slower than its calibrated estimate and leans
on the SLOW arm below, which is exactly what that arm is for.

Recalibration is one command (run it when the tracer's throughput
changes materially, and commit the regenerated table)::

   python -m champsim_tracer_validator lldet_calibrate \
       --build-dir ../../../../build -o /tmp/cal --write

**Condition sampling at the threshold.**  Crossing the deadline never
kills blind.  Two samples ~10s apart measure the qemu process group's
host CPU time, the trace files' size (``*.cst*`` / ``*.body_tmp*``),
the console log's size (system mode), and the group's *written bytes*
(``/proc/<pid>/io`` ``wchar``).  The write counter is load-bearing: with
``compress=`` the on-disk body can sit at zero bytes for an entire
healthy run while the compressor buffers, so file sizes alone would
accuse a healthy cell — ``wchar`` counts the plugin's writes into the
compress pipe and moves whenever the tracer emits.  The classification:

=============  ===================================  =========================
verdict        condition                            action
=============  ===================================  =========================
``DEADLOCK``   zero CPU delta, zero output growth   kill; verdict + stacks
``LIVELOCK``   CPU burning, zero output growth      kill; verdict + stacks
``SLOW``       output still growing                 extend the deadline
                                                    (bounded, logged); kill
                                                    only if a later sample
                                                    stops growing
=============  ===================================  =========================

The SLOW arm is the difference between this and a flat timeout: a
healthy cell on a loaded host is slow, not stuck, and is never killed
while it provably progresses.  The only bound on a progressing cell is
the hard ceiling (12x the calibrated timeout), which names itself
(``HARD_CEILING``) rather than masquerading as a guest verdict.

A watchdog kill is loud by construction: the verdict line
(``[lldet] VERDICT: LIVELOCK -- ...``), both samples, and a
``gdb -p`` all-thread backtrace (the child is made ptraceable via
``prctl(PR_SET_PTRACER_ANY)``) go to stdout, to a ``<outfile>.lldet``
sidecar, and — for system cells — into the guest console log after the
kill.  The run exits 89 (``LLDET_EXIT``), distinct from the plugin's
own progress-gate exit 88.  In system mode the watchdog *complements*
``run_with_clock_watchdog``'s guest-clock legs: the clock legs watch
the guest's user-instruction clock once the window opens; lldet watches
the host process, so a qemu that wedges *before the window ever opens*
— invisible to the clock legs by design — is still bounded and named.

Environment knobs: ``CST_LLDET=off`` disables the watchdog,
``CST_LLDET_K`` / ``CST_LLDET_TIMEOUT`` override the deadline,
``CST_LLDET_TABLE`` points at an alternate table.

For ad-hoc cell harnesses outside the validator there is a standalone
wrapper, ``validator/lldet_watch.py`` (deployed as
``/mnt/md0/QEMU/cst_runs/lib/lldet_watch``)::

   lldet_watch --isa mipsel --mode system --smp 2 --budget 150000 \
       --growth-prefix "$CELL/out" --console "$CELL/console" -- \
       qemu-system-mipsel ...

All three verdicts have been proven to fire (an instrument that has
never fired is not an instrument): a SIGSTOPped healthy qemu is named
``DEADLOCK`` with a frozen CPU counter in the evidence; a spinning
workload under a window that never opens is named ``LIVELOCK`` at 1.00
cores with the TCG-loop backtrace; and a healthy cell contending with
CPU burners on its core crosses its deadline, is extended while its
output grows, completes, and exits 0.

Adding new validator coverage
-----------------------------

Two common paths:

**A coverage probe** (single ISA-targeted block; per-ISA inline asm).
Add an entry to ``_probe_specs.py``:

.. code-block:: python

   _register_probe('probe_x86_lock_xadd', {
       'x86_64': {
           'asm': '"lock xaddq %%rax, (%%rsp)\\n\\t"',
           'clobbers': '"rax","memory","cc"',
           'opcodes': ['XCHG'],
       },
   })

Probes are coverage-probe-only (not selected by the random diamond
walker), so they only run with ``--coverage``.  The validator's
``opcode_coverage`` and ``static_reg_sets`` checks will already pick
them up.

**A new structural check** (any new tracer-side invariant).  Add a
``_check_<name>`` function to ``validator.py`` returning a list of
``Issue`` objects, wire it into ``validate()`` (and
``validate_structural()`` if it doesn't need ``meta.json``).  Each
check should be a single named axis with one info-level summary on
success and explicit errors when it diverges — the report's grouping
already handles aggregation.

Running on a CI matrix
----------------------

The lightweight smoke is ``tests/run_roundtrip.sh``:

.. code-block:: console

   $ tests/run_roundtrip.sh

For broader coverage, drive ``all`` over the ISA matrix in a loop;
combine with ``simpoint_test`` and ``thread_test`` to exercise the
segment / multi-thread paths.  A representative CI block:

.. code-block:: bash

   set -e
   for ISA in x86_64 aarch64 riscv64 mipsel; do
     python3 -m champsim_tracer_validator all \
         --seed 0x0102 -o out/ --isa "$ISA" \
         --build-dir build --regdata --iframe-rate 3 --coverage
     python3 -m champsim_tracer_validator simpoint_test \
         --seed 0x0102 -o out/ --isa "$ISA" \
         --build-dir build --regdata
     python3 -m champsim_tracer_validator thread_test \
         --isa "$ISA" -o out/ --build-dir build --regdata
   done

All three subcommands exit non-zero on the first error-level issue,
so this loop fails fast at the first regression.
