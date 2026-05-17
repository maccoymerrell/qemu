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
    └── champsim_tracer_validator/
        ├── __main__.py            # CLI entry point
        ├── generator.py           # diamond-CFG / probe-coverage emitter
        ├── analyzer.py            # ELF post-processor (PC spans, helper leaf)
        ├── asm_blocks.py          # CodeBlock library + _register_probe
        ├── _probe_specs.py        # inline-asm coverage probes
        ├── _thread_test_asm.py    # hand-written 2-thread programs
        ├── validator.py           # the ~25 named checks
        ├── classify.py            # per-ISA reg classification scanning
        ├── _cst_decode_runner.py  # parses cst_decode's legacy output
        ├── _diff_entries.py       # entry-level diff helper
        └── tests/run_roundtrip.sh # default smoke shell-out

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
   loaded, supplying ``trace_window=icount:start=0;stop=N`` (or
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
   Use ``trace_window=symbol:name=NAME;simulation=<stop>`` instead of
   the default icount-based window.  The validator trims
   ``correct_path`` to start at ``NAME``'s block, so symbol-based
   traces still get full CP / WP validation.

``--hot-iters N``
   Inject a loop region into one of the diamond sides, running for N
   iterations.  Useful for pushing the trace past short-program
   icount budgets when testing simpoint mode.

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
   asserts both threads are visible.

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
   Single-thread runs must produce zero BODY_TAG_THREAD_SWITCH
   records; multi-thread runs must produce at least one (otherwise
   no interleaving was captured).

``thread_distribution``
   Every expected thread contributed entries; no entries reference a
   ``thread_id`` outside ``[0, expected_threads)``.

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

``indirect_wp_assertions``
   Validates the specific ``indirect_wp_one_target`` /
   ``indirect_wp_multi_target`` probe blocks' expected WP-target
   patterns.

``plugin_cp_tail_dropped``
   Diagnostic: surfaces the (known) plugin behaviour of dropping
   the CP entry for the final TB when it ends in a process-exiting
   syscall, so downstream checks don't false-fail on the missing
   tail block.

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
#. Runs ``trace_window=simpoint:file=...;interval=N;simulation=M``
   under the plugin.  The plugin writes each segment to its own
   file: ``<prog>_<isa>_sp0.cst``, ``<prog>_<isa>_sp1.cst``.
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
