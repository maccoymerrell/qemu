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

Capstone is required: the tracer's per-ISA classifier consumes
Capstone's instruction-id, operand, and register-id reporting to
populate ``InsnFields`` and ``InsnRegNames``.  Capstone is wired in
through the Meson wrap at ``subprojects/capstone.wrap``; the
configure step downloads and builds it under
``subprojects/capstone/`` automatically for targets that need it.

Running the tracer
------------------

Attach the plugin to a user-mode QEMU invocation with ``-plugin``:

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run.cst,depth=64 \
                 ./your_program

The plugin name before the comma is followed by ``key=value`` pairs
parsed by ``parse_plugin_options`` in
``champsim_tracer_plugin_config.cc``.  Unknown keys cause the plugin
to refuse to install (the entire QEMU run aborts before the guest
starts).  Numeric values are parsed with ``atoi`` (decimal) for the
small-int options and with ``g_ascii_strtoull`` (decimal,
arbitrary-precision) for the icount-shaped options.

The options are grouped by responsibility below.  Defaults come from
the ``PluginConfig`` struct in
``champsim_tracer_plugin_config.h``; the "applied default" line for
each option says what the global ends up holding when you don't pass
the flag.

Output destination
~~~~~~~~~~~~~~~~~~

``outfile=<basename>``
   Basename for the trace files.  Default ``champsim_tracer_out``.
   The plugin writes:

   * ``<basename>.cst`` — the binary trace.  *The ``.cst`` suffix is
     appended unconditionally even if you already included one in*
     ``basename`` *— so* ``outfile=run.cst`` *produces*
     ``run.cst.cst``.  Use a bare basename to avoid surprise.
   * ``<basename>.unknown_warnings.log`` — sidecar with one line per
     Capstone-emitted instruction the per-ISA classifier didn't
     recognise.  Empty when the classification table covers your
     workload.

   Cannot be combined with ``outpipe`` — the segment manager checks
   whichever is set and uses that one.

``outpipe=<shell command>``
   Shell command run via ``popen()`` to which the binary trace is
   piped.  Default unset.  Avoids landing the trace on disk
   uncompressed; the typical use is ``outpipe="zstd -T0 -19 -o
   run.cst.zst"``.  Mutually exclusive with ``outfile``.

Segmentation
~~~~~~~~~~~~

These options carve up the run into one or more *segments*.  Each
segment produces an independent window of trace records inside the
same output file (i.e., one ``.cst`` covers all segments; segments
appear sequentially in the body stream and are demarcated by their
icount range in the per-segment statistics summary).

``start=<icount>``
   Open the (single) segment when the guest instruction counter
   reaches this value.  Default ``0`` — segment opens at process
   start.  No-op when ``spfile`` is set (simpoint mode overrides the
   single-window window).

``stop=<icount>``
   Close the (single) segment and call ``exit(0)`` from
   ``vcpu_tb_exec`` when the guest instruction counter reaches this
   value.  Default ``UINT64_MAX`` — never stop early; the trace runs
   to natural process exit.  Combine with ``start`` to carve a
   contiguous window.  No-op when ``spfile`` is set.

``spfile=<path>``
   Path to a SimPoint file.  When set, replaces the single
   ``[start, stop)`` window with one segment per simpoint interval
   listed in the file.  ``trace_start_insn`` is forced to 0 and
   ``trace_stop_insn`` to ``UINT64_MAX`` so the simpoint manager has
   full authority.  Cannot be combined with ``start`` / ``stop`` (they're
   silently ignored, not an error).

``spinterval=<insns>``
   Instructions per simpoint interval.  Default ``100000000``
   (100 M).  Must match the granularity used to *generate* the
   simpoint file — a 100 M-interval simpoint file with this option
   set to 10 M would carve windows at 1/10 the intended boundaries.

Wrong-path simulation
~~~~~~~~~~~~~~~~~~~~~

``wp=0`` / ``wp=1``
   ``1`` (default) enables wrong-path simulation: every CP branch
   gets a speculative chain of WP basic blocks attached to its body
   record.  ``0`` disables WP entirely — the trace records only the
   correct path, the WP chain count is always zero, and runtime
   drops considerably (typically 2-3×) because no
   ``cpu_plugin_exec_tb`` calls happen.  Useful when you only want a
   CP trace for a non-speculative simulator.

``depth=<insns>``
   Wrong-path *budget* in speculative instructions per branch.
   Default ``64``.  The WP simulator stops the speculative chain as
   soon as ``sim_insns >= depth`` *and* the in-flight WP basic block
   has finished (i.e., the loop won't truncate a BB mid-flight).
   Bigger values give a longer speculative shadow per branch but
   linearly increase runtime on misprediction-heavy workloads —
   doubling ``depth`` roughly doubles the WP work.  Setter rejects
   non-positive values.

Capture flags
~~~~~~~~~~~~~

These control how much *dynamic* per-execution data is captured
beyond the static templates.  Templates are mandatory; everything
below is opt-in because it can substantially grow the trace.

``memdata=0`` / ``memdata=1``
   ``0`` (default) records only memory access *addresses* (load and
   store vaddrs).  ``1`` additionally captures the *value* loaded or
   stored, up to 64 bytes per access — the wire format encodes them
   under ``CST_FID_LOAD_DATA*`` / ``CST_FID_STORE_DATA*``.  Needed
   by data-aware consumers (correctness simulators, value-prediction
   research); typical cache-and-prefetcher work doesn't use it.

``regdata=0`` / ``regdata=1``
   ``0`` (default) records no register values.  ``1`` snapshots each
   instruction's *source* register values immediately before it
   executes, encoded under ``CST_FID_SRC_REG*``.  Destination values
   are not captured — the snapshot point is pre-execute.  This is
   the heaviest single capture flag: it adds one read-register
   callback per CP source operand, plus an inline pre-fragment
   wide-regfile dump for WP.

``wp_memdata=0`` / ``wp_memdata=1``
   WP-side override for ``memdata``.  Default *inherits* the value
   of ``memdata`` (i.e., the wire-format flag mirrors CP).  Setting
   this to ``0`` regardless of ``memdata`` keeps the WP memop
   *addresses* but drops the per-access *values*; addresses are
   typically what cache and prefetcher simulators need from WP and
   they're an order of magnitude smaller than the values.  This is
   usually the largest single trace-size knob on speculation-heavy
   workloads.  Note: setting ``wp_memdata=1`` while ``memdata=0`` is
   permitted but unusual — you'd record values on WP only.

``wp_regdata=0`` / ``wp_regdata=1``
   WP-side override for ``regdata``.  Default inherits from
   ``regdata``.  Skips the per-fragment wide-regfile dump on WP when
   off; in practice this saves substantial runtime on WP-heavy
   workloads since the dump touches every architectural register
   the ISA exposes.

Observability
~~~~~~~~~~~~~

``histogram=<N>``
   Default ``0`` — disabled.  When ``N > 0``, ``start_trace_segment``
   allocates ``N`` zero-initialised ``Stats`` buckets and
   ``finish_trace_segment`` walks them after printing the segment
   summary.  Each bucket holds the same counters as ``g_stats``
   (CP / WP opcode, branch type, register attribution, memop
   counts) but scoped to one icount slice of width
   ``ceil(span / N)``.  The buckets are mirrored into in
   ``vcpu_tb_exec`` from ``g_current_hist_bucket``.

   The output is a headline table with one row per interval plus
   transposed top-K tables for opcodes / branch types / source
   registers / destination registers (rows are top items; columns
   are intervals).  Use to spot phase shifts within a long
   simpoint segment.

Trace metadata
~~~~~~~~~~~~~~

These don't affect what's captured; they get stamped into the trace
header for downstream tools to identify the run.

``program=<string>``
   Free-form program identifier written into the header.  Defaults
   to none.  The QEMU command line is also recorded automatically
   in the header's ``command`` field — ``program`` is for friendly
   names like ``"mcf_r refrate run0"``.

``comment=<string>``
   Free-form note recorded in the header's ``comment`` field.
   Defaults to none.

Output files and stderr
-----------------------

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

   from pathlib import Path
   from champsim_tracer_decode import decode_champsim_tracer

   meta, templates, entries = decode_champsim_tracer(Path("run.cst.cst"))
   for entry in entries:
       print(entry["template_id"],
             entry["dyn_params"],
             len(entry["wp_entries"]))

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

Building this documentation
---------------------------

The site you are reading is a Sphinx project under
``contrib/plugins/champsim_tracer/docs/``.  Two output formats are
supported.

HTML (the default)
~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ pip install sphinx furo myst-parser
   $ make -C contrib/plugins/champsim_tracer/docs html
   # open _build/html/index.html

Output lands in
``contrib/plugins/champsim_tracer/docs/_build/html/``.  No TeX
install is required.

PDF (offline / portable)
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ # Same Python deps as HTML, plus a TeX install:
   $ sudo apt install texlive-xetex texlive-latex-recommended \
                      texlive-fonts-recommended latexmk
   $ make -C contrib/plugins/champsim_tracer/docs latexpdf
   # PDF: contrib/plugins/champsim_tracer/docs/_build/latex/champsim_tracer.pdf

``make pdf`` is an alias.  The build uses XeLaTeX (driven by
``latexmk``) so the output handles UTF-8 in code blocks and the
encoding-map names without surprise.  Paper size is letter; flip
``latex_elements["papersize"]`` in ``conf.py`` to ``"a4paper"`` for
A4.

The GitHub Actions workflow at
``.github/workflows/champsim-tracer-docs.yml`` builds both HTML and
PDF on each push to ``champsim-trace`` that touches the docs;
HTML deploys to Pages, the PDF is also attached as a downloadable
``champsim_tracer-pdf`` workflow artifact.  PDF build failure does
not fail the workflow — HTML still ships.
