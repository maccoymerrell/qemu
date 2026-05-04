Quickstart
==========

This page covers building the plugin, running it against a guest, and
reading the trace it produces.

Building
--------

The tracer builds as part of QEMU's contributed plugins:

.. code-block:: console

   $ ./configure --enable-plugins
   $ ninja -C build contrib/plugins/libchampsim_tracer.so

Capstone (vendored under ``subprojects/capstone``) is required: the
tracer uses its disassembler to classify generic opcodes / branch
types / register sets.  The configure step pulls it in automatically
for the QEMU targets that need it.

Running the tracer
------------------

Attach the plugin to a user-mode QEMU invocation with ``-plugin``:

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run.cst,depth=64 \
                 ./your_program

The plugin name in front of the comma is followed by ``key=value`` pairs.
Recognised options:

.. list-table::
   :header-rows: 1
   :widths: 20 12 60

   * - Option
     - Default
     - Meaning
   * - ``outfile``
     - ``champsim_tracer_out``
     - Output file basename.  ``.cst`` is appended; an
       ``.unknown_warnings.log`` sidecar collects decode warnings.
   * - ``outpipe``
     - (none)
     - Shell command to ``popen()`` instead of writing to disk.  Useful
       for piping into a compressor (``zstd -T0 -19``) inline.
   * - ``depth``
     - 64
     - Wrong-path simulation budget, in *speculative instructions* per
       branch.  Burns more time on misprediction-heavy workloads.
   * - ``wp``
     - 1
     - ``0`` disables WP simulation entirely (CP-only trace).  Cuts
       runtime ~2-3× but loses the speculative shadow ChampSim wants.
   * - ``memdata``
     - 0
     - When ``1``, capture the *value* of every CP load and store, not
       just the address.  Adds wire bytes; needed by simulators that
     - care about mem-data.
   * - ``regdata``
     - 0
     - When ``1``, snapshot each instruction's source-register values
       just before it executes.  Heavier than ``memdata``.
   * - ``wp_memdata``
     - inherits ``memdata``
     - Override for the WP path: ``0`` keeps WP memop *addresses* (which
       are what cache simulators need) but drops the per-access
       *values*.  Typically the largest single trace-size knob.
   * - ``wp_regdata``
     - inherits ``regdata``
     - Override for the WP path's register-snapshot capture.
   * - ``start``
     - 0
     - Skip past this many guest instructions before opening a trace
       segment.  Lets you fast-forward past startup.
   * - ``stop``
     - ``UINT64_MAX``
     - Close the segment and exit when guest instruction count reaches
       this value.  Pair with ``start`` to carve a single window.
   * - ``spfile``
     - (none)
     - Path to a SimPoint file.  When present, the tracer emits one
       segment per simpoint interval in the file instead of a single
       window.
   * - ``spinterval``
     - ``100000000``
     - Instruction count per simpoint interval (must match how the
       simpoints were generated).
   * - ``program``
     - (none)
     - Stamped into the trace header for downstream identification.
   * - ``comment``
     - (none)
     - Free-form note, also stamped in the header.
   * - ``histogram``
     - 0
     - When non-zero, partition each segment's icount span into N
       equal intervals and append a per-interval breakdown of CP/WP
       insns, memops, branches, and top-K opcode/branch/reg tables to
       the segment summary.  See :doc:`architecture`.

Output
------

Three files land beside the basename:

* ``<outfile>.cst`` — the binary trace.
* ``<outfile>.unknown_warnings.log`` — Capstone-flagged instructions the
  generic-opcode mapper didn't recognise.  Empty on a clean run.
* ``stderr`` — segment lifecycle (``starting segment``, 10 % progress
  ticks, ``finished segment``) plus a final statistics summary
  containing CP/WP totals, branch-type breakdown, opcode usage, and
  register attribution.

Reading the trace
-----------------

The Python decoder turns the binary into structured records:

.. code-block:: python

   from champsim_tracer_decode import iter_entries, parse_trace_meta

   meta, entries = parse_trace_meta("run.cst.cst")
   for entry in iter_entries("run.cst.cst", meta):
       print(entry.template_id, entry.dyn_params, len(entry.wp_entries))

A byte-budget audit (helpful when tuning trace size) is one command:

.. code-block:: console

   $ python3 cst_audit.py run.cst.cst
   FILE                                     12.34 MiB  100.00%
   === TOP-LEVEL SECTIONS ===
     HEADER                                  6.18 KiB    0.05%
     TEMPLATES                              412.30 KiB    3.27%
     BODY                                    11.94 MiB   96.66%
     TRAILER                                      64 B    0.00%
   ...

For the full decoder API see :doc:`decoder`.
