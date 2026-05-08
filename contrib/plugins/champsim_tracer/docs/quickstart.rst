Quickstart
==========

This page covers building the plugin, running it against a guest, and
reading the trace it produces.

Building
--------

Prerequisites
~~~~~~~~~~~~~

The tracer is a C++17 QEMU TCG plugin.  Tested combinations:

* **OS:** Ubuntu 22.04 / 24.04, Debian 13, Fedora 40.  Other
  Linuxes likely work; macOS is untested; Windows builds via the
  meson plumbing but is not exercised in CI.
* **Compiler:** gcc 11+ or clang 14+.  C++17 is required.
* **glib:** 2.66 or newer (Ubuntu 22.04 default is fine).
* **Capstone:** auto-downloaded by meson via
  ``subprojects/capstone.wrap``.  The plugin uses Capstone's
  detail mode + group classification, so the wrap version is
  what we test against.
* **QEMU base:** the repository is a fork of QEMU.  The plugin
  expects the base modifications described in
  :doc:`qemu_modifications`; building against an unmodified
  upstream QEMU will not work because the plugin uses
  ``qemu_plugin_insn_detail`` and ``qemu_plugin_cap_decode``,
  which were added on this fork.

Build invocation
~~~~~~~~~~~~~~~~

A reduced-target configure that builds only the user-mode targets
the tracer supports:

.. code-block:: console

   $ ./configure --enable-plugins \
                 --target-list=x86_64-linux-user,aarch64-linux-user,riscv64-linux-user,mipsel-linux-user
   $ ninja -C build contrib-plugins

``contrib-plugins`` is the alias target that builds the plugin
shared object and the offline tools (``cst_decode``, ``cst_audit``)
in one shot.  Output lands under ``build/contrib/plugins/``.

A full configure (system mode included) also works; the user-mode
restriction above just trims build time.  Capstone is downloaded
and built automatically the first time you ``configure`` for a
target that needs it.

If your distribution ships a stale Capstone (some do), the meson
wrap takes precedence — the plugin always builds against the wrap
copy under ``subprojects/capstone/``.

Running the tracer
------------------

Attach the plugin to a user-mode QEMU invocation with ``-plugin``:

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wpdepth=64 \
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

   * ``<basename>.cst`` — the binary trace.  A trailing ``.cst`` in
     the user-supplied basename is stripped before the suffix is
     appended, so ``outfile=run`` and ``outfile=run.cst`` both produce
     ``run.cst``.  In simpoint mode the per-segment files are named
     ``<basename>_sp<index>.cst`` (the trailing ``.cst`` on the user
     basename is also stripped for these).
   * ``<basename>.unknown_warnings.log`` — sidecar with one line per
     Capstone-emitted instruction the per-ISA classifier didn't
     recognize.  Empty when the classification table covers your
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

``warmup=<insns>``
   Number of instructions to trace *before* each simpoint position so
   downstream simulators can prime their caches and branch predictors
   on real upstream behaviour before the evaluation window opens.
   Default ``0``.  Only consulted in simpoint mode.  The effective
   segment start becomes ``max(0, sp->start_insn - warmup)``; the
   header records the actual warmup-length as ``warmup_insns`` so
   consumers can split the trace at that offset.

``simulation=<insns>``
   Number of instructions to trace *at and after* each simpoint
   position (the evaluation window).  Default ``0``, which falls back
   to the legacy ``simpoint_interval`` length.  When set explicitly,
   each simpoint segment runs ``warmup + simulation`` instructions
   total: a ``warmup=100000000,simulation=100000000`` run on a
   simpoint at icount 100 M produces a single segment covering the
   instruction range ``[0, 200 M)``.

Wrong-path simulation
~~~~~~~~~~~~~~~~~~~~~

**What "wrong-path" means here.**  At every CP branch the tracer
runs an extra side-trip: it picks the *other* target the branch
predictor might have chosen and runs basic blocks down that path
until ``wpdepth`` instructions have been speculatively fetched.
The simulator drives QEMU's TCG to actually execute those
instructions, mutating registers and attempting stores, so the
recorded WP chain reflects the architectural state a real
mispredicting machine would have produced.  Stores route through
a per-vCPU speculative store buffer rather than touching guest
memory; loads see that buffer overlaid on the real address space.
At the end of each WP chain the saved CPU state is restored — the
correct path resumes from exactly where the branch was first
observed, mirroring how a real machine squashes the wrong-path
work when the misprediction is resolved.

This is the right shape for cache-pollution and prefetcher-
training research: the recorded WP entries carry the same memops
and register snapshots a real machine's speculative window would
generate.  It is *not* a cycle-accurate model — branch-mispredict
penalty timing lives in the consumer simulator, not the trace —
and it does not nest mispredicts: branches *inside* the
speculative window follow their statically-resolved direction
rather than spawning further wrong-path chains.

``wp=0`` / ``wp=1``
   ``1`` (default) enables wrong-path simulation: every CP branch
   gets a speculative chain of WP basic blocks attached to its body
   record.  ``0`` disables WP entirely — the trace records only the
   correct path, the WP chain count is always zero, and the run is
   roughly an order of magnitude faster (measured ~16× on
   ``mcf_r``: see :doc:`architecture` for the full table).
   Useful when you only want a CP trace for a non-speculative
   simulator.

``wpdepth=<insns>``
   Wrong-path *budget* in speculative instructions per branch.
   Default ``64``.  The WP simulator stops the speculative chain as
   soon as ``sim_insns >= wpdepth`` *and* the in-flight WP basic
   block has finished (i.e., the loop won't truncate a BB mid-flight).
   Bigger values give a longer speculative shadow per branch but
   linearly increase runtime on misprediction-heavy workloads —
   doubling ``wpdepth`` roughly doubles the WP work.  Setter rejects
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
   instruction's *destination* register values immediately after it
   executes, encoded under ``CST_FID_DST_REG*``.  Source values are
   not captured — destinations strictly dominate (they cover every
   architectural write, so consumers can derive any register's value
   at any point from the most recent post-write observation, and
   there are typically fewer destinations than sources per insn).
   The CP capture point is the pre-exec hook of the *next* canonical
   instruction (so we observe registers between the just-finished
   insn's writes and the next insn's reads); the tail insn of each
   TB is captured at the next TB's tb_exec.  WP uses a wide
   post-fragment regfile snap.

``wp_memdata=0`` / ``wp_memdata=1``
   WP-side override for ``memdata``.  Default *inherits* the value
   of ``memdata`` (i.e., the wire-format flag mirrors CP).  Setting
   this to ``0`` regardless of ``memdata`` keeps the WP memop
   *addresses* but drops the per-access *values*; addresses are
   typically what cache and prefetcher simulators need from WP, and
   on speculation-heavy workloads dropping WP data values is one of
   the larger trace-size knobs.  Measured impact on the
   architecture page's mcf table: full data → WP-addresses-only
   takes the trace from 548 MB to 280 MB on a 20 M-insn run.
   Setting ``wp_memdata=1`` while ``memdata=0`` is permitted but
   unusual — you'd record values on WP only.

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
   allocates ``N`` zero-initialized ``Stats`` buckets and
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

``iframe_rate=<N>``
   Default ``0`` — disabled.  When ``N > 0``, every Nth observation
   of a CP template is followed by a redundant ``BODY_TAG_IFRAME``
   body record encoded against fresh template-default baselines
   (i.e., absolute values).  Decoders use these to cross-check that
   their delta-replay reconstructed the same view the writer had —
   a mismatch raises an error in ``cst_decode``.
   The IFRAME covers the *entire* body record (CP + WP chain + WP
   events), so flagging the CP also IFRAMEs every WP entry attached
   to it.  Pure overhead: a trace produced with ``iframe_rate=0``
   contains no IFRAME records.  Each IFRAME costs roughly the
   absolute-encoded size of the body record it's snapshotting —
   ``cst_audit`` reports the total IFRAME byte count under "IFRAME
   records (validation redundancy)".

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

Common configurations
---------------------

Recipes for the typical research targets.  Each line is a single
``-plugin`` invocation; replace ``./prog`` with your workload.

**Cache + prefetcher trace for ChampSim-style consumers**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,memdata=0,wp_memdata=0 \
                 ./prog

Captures CP and WP load / store *addresses* (no values).  WP
memops are kept (cache-pollution stream) but their values are
dropped — the dominant trace-size knob on speculation-heavy code.

**Branch-prediction trace**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,wpdepth=128,memdata=0,regdata=0 \
                 ./prog

Smaller still: no memory data, no register data, but every branch
in the trace has both its actual outcome and the wrong-path
shadow used by mispredict-penalty studies.  ``wpdepth=128``
lengthens the speculative window when you want to see further
into the alternate path.

**Value-prediction / data-aware trace**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,memdata=1,regdata=1 \
                 ./prog

Most expensive configuration: every memop value and every
destination-register write is recorded.  Trace size grows with
the workload's data footprint; pipe through ``zstd`` (see the
``outpipe=`` flag above) when running long workloads.

**Long-workload simpoint capture**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,\
   outfile=run,wp=1,spfile=run.simpts,spinterval=100000000,\
   warmup=100000000,simulation=100000000 \
                 ./prog

One per-simpoint ``.cst`` file with 100 M warmup + 100 M evaluation
instructions per segment.  Drives ChampSim-style sampled simulation
on multi-billion-instruction workloads in tractable trace volume.

**CP-only trace for a non-speculative simulator**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=0,memdata=0 \
                 ./prog

Smallest, fastest configuration.  No WP chain, no memory data —
just the architectural correct path with addresses.

Output files and stderr
-----------------------

Three files land beside the basename:

* ``<outfile>.cst`` — the binary trace.
* ``<outfile>.unknown_warnings.log`` — Capstone-flagged instructions the
  generic-opcode mapper didn't recognize.  Empty on a clean run.
* ``stderr`` — segment lifecycle (``starting segment``, 10 % progress
  ticks, ``finished segment``) plus a final statistics summary
  containing CP/WP totals, branch-type breakdown, opcode usage, and
  register attribution.

Reading the trace
-----------------

``cst_decode`` (built next to the plugin) emits a greppable
disassembly-style dump:

.. code-block:: console

   $ build/contrib/plugins/cst_decode run.cst | head
   ; cst_decode disassembly
   ; version=0x19545343
   ; isa=x86_64
   ...
   0x401a23 <main+0x83>: GEN_OP_ADD  REG_GPR1,REG_FLAGS <- REG_GPR2,REG_GPR3  ; tid=0 bb=42 REG_GPR1=0x1f
   0x401a27 <main+0x87>: GEN_OP_ST_W REG_FLAGS <- REG_GPR1,REG_GPR15,IMM(0x8) ; tid=0 bb=42 st@0x7fff_dead_beef:0x1f

Each line is self-contained — pipe it through ``grep`` by PC,
opcode, register, ``bb=`` id, ``ld@``/``st@``, branch type, etc.
Pass ``--format=legacy`` to get the older block-formatted output
that diff-driven scripts (notably wptrace_genval) consume.

A byte-budget audit (helpful when tuning trace size) is one command:

.. code-block:: console

   $ build/contrib/plugins/cst_audit run.cst
   FILE                                     12.34 MiB  100.00%
   === TOP-LEVEL SECTIONS ===
     HEADER                                  6.18 KiB    0.05%
     TEMPLATES                              412.30 KiB    3.27%
     BODY                                    11.94 MiB   96.66%
     TRAILER                                      64 B    0.00%
   ...

For both tools' full surface see :doc:`decoder`.

.. _reproducibility:

Reproducibility
---------------

The trace is deterministic in the following sense: given the same
guest binary, the same QEMU command line, the same plugin flags,
and the same plugin build, two runs produce body streams that are
*architecturally identical* — every basic block invoked, every
memop, every register snapshot matches across runs.  In practice
two ``.cst`` files from back-to-back runs typically differ in two
places:

* ``DATETIME`` and ``COMMAND`` strings inside the per-segment
  header.  Both are recorded as-is.
* The order of identifiers in the encoding-maps section, when
  unordered hash-table iteration orders something — the C++
  writer sorts the templates dictionary on serialization, so
  template_id assignments stable across runs.

Things that *can* break determinism:

* **ASLR.**  Virtual addresses in the trace are guest-mode virtual
  addresses; if the guest randomizes its layout, the body stream's
  ``LOAD_ADDR`` / ``STORE_ADDR`` slots and the templates'
  ``start_pc`` values will shift accordingly.  Disable ASLR via
  ``setarch -R`` on the QEMU command for byte-stable traces.
* **Concurrency.**  Multi-threaded guest workloads can interleave
  vCPUs differently across runs.  See :ref:`multi-vcpu` in the
  architecture doc.
* **Wall-clock-dependent guest behavior.**  Workloads that
  dispatch differently based on ``gettimeofday()`` etc.  The
  tracer records the divergence faithfully; if you want bit-stable
  traces, fix the workload's clock.

Cross-host reproducibility holds when the above sources are
controlled — the same guest binary produces the same trace on two
different hosts running the same QEMU+plugin build.  Cross-QEMU-
version reproducibility is *not* guaranteed: if the QEMU base
moves to a different upstream commit, the TB carving heuristics
may shift, which renumbers ``template_id`` in the dictionary.
The body's architectural content stays the same.

Feeding ChampSim
----------------

ChampSim itself doesn't yet consume the ``.cst`` format directly —
ChampSim's stock trace path takes its own ``instr_t``-shaped binary.
A ``.cst`` → ChampSim adapter is the consumer's responsibility for
now: the trace exposes everything ChampSim needs (per-instruction
PC, branch type and outcome, load/store addresses, optional values,
wrong-path chain), but the marshalling of those fields into
ChampSim's expected layout lives outside this repository.

Until a first-party converter ships, the recommended consumer
pattern is:

1. Iterate body entries with ``cst_decode --format=disasm`` (one
   line per architectural instruction, easy to grep) or via a
   custom C++ consumer linked against ``libcst_tools_common`` (the
   static library the offline tools share — header-only API in
   ``contrib/plugins/champsim_tracer/tools/``).
2. Convert per-record fields into the simulator's expected
   structure on the fly.  Templates are loaded once at the start
   of the trace and kept in memory; body entries stream past one
   at a time so memory stays bounded regardless of trace length.

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

   $ # Same Python deps as HTML, plus a TeX install with FreeSerif:
   $ sudo apt install texlive-xetex texlive-latex-recommended \
                      texlive-fonts-recommended fonts-freefont-otf \
                      latexmk
   $ make -C contrib/plugins/champsim_tracer/docs latexpdf
   # PDF: contrib/plugins/champsim_tracer/docs/_build/latex/champsim_tracer.pdf

.. note::

   ``fonts-freefont-otf`` is required separately on
   Debian/Ubuntu — Sphinx's ``xelatex`` template selects FreeSerif
   as the default body face, and ``texlive-fonts-recommended``
   alone does not include it.  Without it the build aborts at
   ``fontspec Error: The font "FreeSerif" cannot be found``.

``make pdf`` is an alias.  The build uses XeLaTeX (driven by
``latexmk``) so the output handles UTF-8 in code blocks and the
encoding-map names without surprise.  Paper size is letter; flip
``latex_elements["papersize"]`` in ``conf.py`` to ``"a4paper"`` for
A4.

The GitHub Actions workflow at
``.github/workflows/champsim-tracer-docs.yml`` builds the HTML on
each push to ``champsim-trace`` that touches the docs and deploys
it to Pages.  PDF is *not* built in CI — the texlive install adds
several minutes per run and the portable copy is only useful to a
small fraction of readers.  Run ``make pdf`` locally when you need
one.
