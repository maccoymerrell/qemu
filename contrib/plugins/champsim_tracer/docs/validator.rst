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
#. **trace** — run the binary under ``qemu-<isa>`` with the plugin
   loaded, supplying ``trace_window=icount:start=0+stop=N`` (or
   ``trace_window=symbol:...`` / ``trace_window=simpoint:...``) and
   ``memdata=1[,regdata=1]``.
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
   opens + ASID-pins the window (``trace_window=marker``).  Implies
   ``--marker`` at generation, which also injects the close(-1)
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
   ratio past 20 (healthy runs sit between 1 and 8.5), and a
   user-instruction clock that stops advancing in wall time.  The
   first two are asserted by ``_check_segment_coverage`` — so every
   system-mode check in the suite carries them — and the third by a
   live watchdog in the system trace path, which also bounds a
   wedged run's cost, since a spinning guest never exits on its own.

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
   cleanly.  **Non-gating** — whether the detector or the guest's
   poweroff backstop closes the window first is wall-clock/scheduling
   sensitive; the trace well-formedness assertions still run once it
   closes.

**features** — 13 checks.  Plugin options and wire records that no
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
   list).
``features.devio_attrib``
   Exact-owner disk-I/O attribution: two CONCURRENTLY marked
   processes (``-smp 2``, disjoint LBA bands) must each own only
   their own band's ``DEVIO_START`` records.
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
``features.options_smoke``
   Direct qemu-user drive of the long-tail options no other check
   sets (``histogram``, ``wp_memdata``, ``wp_regdata``,
   ``program``/``comment``); asserts the trace decodes clean.
``features.mutation_strictness``
   The :ref:`mutation <validator-mutation>` matrix, run in-process.
``features.wrong_path_coverage``
   ``static_templates=1`` fall-through / BTB coverage oracle across
   all four ISAs (minted-alternate blocks, deepened by
   ``static_depth``), with a minting-off run proving the oracle has
   teeth.
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
   17 of the 23 catalogue entries are this layer: flipping a captured
   dst-register value or misattributing it to the wrong register id,
   swapping two memop addresses or flipping a captured load/store data
   byte, relabeling a pinned instruction's opcode class or branch
   classification, flipping a raw instruction byte in a template,
   truncating / reordering the first two blocks of a predicted
   wrong-path chain, a depth-0 WP missequence paired with a later
   synthetic fault mark (the fault must not excuse the earlier
   divergence), reordering two correct-path entries, forging a
   foreign guest-thread id onto an entry, corrupting a per-memop
   physical-page value, dropping a ``DEVIO_STOP`` record, corrupting a
   self-modified block's non-baseline revision bytes, and corrupting a
   *shape-changed* revision's bytes (a revision minted at a different
   instruction count than the block's original template — the class
   only shape-agnostic minting produces).  The DEVIO and SMC mutations
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
   truncating the body member payload.
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
   equally valid catch. 2 catalogue entries: flipping the WP chain
   header's ``CST_WP_CHAIN_HAS_EVENTS`` presence bit set→clear on a
   chain that has an events section, and clear→set on a chain that
   doesn't.

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
   target).  A kernel excursion (``is_system`` entries) may resume the
   thread at a redirected PC, so it breaks the chain and the first user
   entry after it restarts without penalty.  A disconnect within a
   tid's own chain is an *orphan*: a dropped user block, a phantom
   entry, or foreign code leaking past the pin.  Matching per tid (not
   globally against a live set) cannot launder one thread's block onto
   another's successors, so it is strictly stronger than the
   pre-identity check; ``chains`` in the info detail is the number of
   distinct guest threads that contributed user entries.  Runs in
   ``validate_structural`` (``thread_test``, ``churn_test``); not yet
   wired into the ``all`` battery — it correctly fails on a known
   fault-merge defect (see the comment at the ``validate()`` call
   site).

``thread_strand``
   Sequentiality of every ``(thread_id, asid)`` context — the property a
   consumer relies on when it keys per-thread state on that pair and
   reads the entries under one key as a single instruction stream.
   Where ``thread_chain`` follows *user* code per thread, this check
   walks the whole stream, kernel included, and uses each entry's
   resolved terminal branch: filtered to one context, entry N's branch
   target should name entry N+1's start PC (or one of its fault anchors,
   for a merged block).  When it does not, the strand was diverted, and
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

``syscall_fault_nesting``
   Nested-excursion discipline (system-mode marker runs).  The
   generated marker workload issues one syscall whose kernel path is
   guaranteed to fault — ``sysinfo`` writing into a never-touched
   demand-zero page (``emit_trace_fault_probe``; the buffer sits
   64 KiB past the .data tail so no guest page size up to 64 KiB
   pre-maps it) — so the trace must contain at least one user-syscall
   excursion with ``fault_depth >= 1`` entries inside it.
   Independent of the probe: per-tid fault depth changes by at most
   one between consecutive entries, and a fault-anchored
   (whole-BB-merged) entry sits at its excursion's unwind.  The
   fault-depth histogram is reported for regression visibility.

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
   of every CP+WP template's per-insn ``is_atomic`` field.

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
   including ``data`` values for ``memdata=1`` runs.

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
   original CFG.

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
invariants).  The ``devio`` and ``physaddr`` record families have their
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
#. Validates each segment file *in reverse order* — explicitly
   touches segment 1 before segment 0 — to prove segment N is
   fully self-decodable without any prior knowledge of segment N-1.

The validation is structural (no ``correct_path`` cross-check —
simpoints intentionally start mid-program where the CFG anchor
isn't available).  Asserted invariants:

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
