Visualizer
==========

.. index::
   single: cst_visualize
   single: visualizer

``cst_visualize`` renders a ``.cst`` trace as a standalone SVG chart.  It
is the third offline C++ tool built next to the plugin (alongside
:doc:`cst_decode and cst_audit <decoder>`) and, like them, reads the wire
format directly with no dependency on the QEMU plugin runtime.  Where
``cst_decode`` answers *what executed* and ``cst_audit`` answers *where the
bytes went*, ``cst_visualize`` answers *how a chosen characteristic evolves
across the run* — branch behaviour, memory-access patterns, instruction
mix, dependency depth, and the speculative-pollution cost of wrong-path
execution.

Each chart bins the trace along the **CP instruction window** — the
architectural correct-path instruction count, accumulated from the body's
basic-block ``n_insns`` — and draws one metric over those bins.  A trace
processed on its own produces a per-trace chart; several traces of one
program processed together produce a single weighted *composition* chart
(see `Aggregate mode`_).

Building and invoking
---------------------

``cst_visualize`` is produced by the same ``ninja contrib-plugins``
invocation that builds the plugin shared object and lands in
``build/contrib/plugins/cst_visualize``.

.. code-block:: console

   $ build/contrib/plugins/cst_visualize -m branch_dir -o branch_dir.svg trace.cst
   $ build/contrib/plugins/cst_visualize -m cache_miss --cache-assoc=1,4,16 -o miss.svg trace.cst

The metric (``-m``) is required; ``-o`` names the output file (default
stdout).  ``--width`` / ``--height`` set the SVG dimensions, ``--bins`` the
number of instruction-window bins, and ``--title`` overrides the chart
title.

Metrics
-------

Metrics fall into five families by what they draw and what trace data they
read.

Time-series breakdowns (stacked area)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each bin is a 100 %-stacked composition of categories.

``branch_dir``
   Branch direction and class breakdown — conditional taken / not-taken,
   plus the always-taken families (direct jump, indirect jump, return,
   syscall).  Dual pane: the correct path on top, the wrong path on the
   bottom.

``mem_pat``
   Memory-access-pattern breakdown (none / regular / irregular / random),
   classified from the captured effective addresses.  Dual pane, CP over
   WP.

``gen_op``
   Generic-opcode mix, top-K opcodes plus an ``other`` bucket.

``gen_reg``
   Destination-register mix, top-K registers plus ``other`` (architectural
   side-effect registers — flags, the program counter, the hardwired zero —
   are excluded so the named GPR / FPR / vector traffic is visible).

Predictor and speculation rates (lines)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One line per swept model parameter; the y-axis is a per-bin rate.

``branch_mpki``
   Branch mispredictions per 1 000 CP instructions under a gshare
   predictor, one line per ``--history`` length.  Dual pane: a CP-only
   predictor over one that is additionally polluted by wrong-path branches.

``btb_miss``
   BTB miss rate, one line per ``--btb-entries`` size.  Dual pane, CP-only
   over WP-polluted.

``cache_miss``
   Cache miss rate, one line per ``--cache-assoc``.  Both panes always
   measure the *CP* miss rate; the bottom pane's cache is additionally
   polluted by wrong-path memory accesses, so the gap between the panes is
   the speculation-induced miss penalty.

``wp_insns`` / ``wp_memops``
   Wasted wrong-path instructions / memory operations per 1 000 CP
   instructions — the speculative work a mispredict would have issued,
   gated by whether the modelled predictor actually mispredicted.

``wp_divergence``
   How many wrong-path instructions a predictor follows before its
   predicted path diverges from the chain the trace recorded — min /
   median / mean / max per bin.

Dataflow (lines)
~~~~~~~~~~~~~~~~~

``dep_depth``
   Dependency-chain depth under a Wall-style ideal-rename model, bounded to
   a tumbling reorder-buffer window of ``--rob-size`` instructions.  The
   chain follows register and memory (store→load) read-after-write edges.

``ilp``
   Ideal IPC under perfect rename over the same window.  Dual pane: per-bin
   IPC on top, an in-window issue-cycle histogram on the bottom.

``working_set``
   Distinct cache lines and 4 KiB pages touched within a sliding window of
   ``--ws-window`` instructions — the live working-set size over program
   phases, not a since-start cumulative footprint.

Static and distribution histograms (bars)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These summarise a distribution rather than evolution over time, so the
x-axis is the measured quantity, not the instruction window.

``bb_length``
   Basic blocks by length in instructions.  Dual pane: one count per static
   template on top, the same weighted by correct-path execution count on
   the bottom.

``indirect_targets``
   Indirect branches by distinct-target count (static and
   execution-weighted).

``branch_entropy``
   Conditional branches by direction entropy (static and
   execution-weighted).

``reuse_distance``
   Memory reuse (stack) distance, log-bucketed, with a leading cold-miss
   bucket.

Long sparse tails on the ``bb_length`` and ``reuse_distance`` histograms
fold into a ``>N`` overflow bin once they fall below ``--hist-tail-pct`` of
the total, keeping the x-axis readable.

Execution context and system-mode metrics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These metrics read the trace's execution-context records — privilege,
fault nesting, threads, address spaces, disk I/O, and physical pages — so
they are at their most informative on system-mode traces.  Each degrades
to a well-defined chart on a trace without the relevant content (an
all-user trace plots a 100 % user share; a single-ASID trace plots one
band), and the feature-gated ones are dropped from the all-metrics pass
when the trace lacks the capability entirely.

``user_kernel``
   User vs kernel instruction share per window, from the per-instruction
   privilege flag.  Stacked.

``fault_rate``
   Synchronous-fault activity.  Dual pane: fault-excursion starts per
   1 000 CP instructions on top; fault-nesting depth (mean across
   handler-resident entries, plus the per-bin maximum) on the bottom.

``thread_switch``
   Thread switches and distinct active threads per window.

``asid_timeline``
   Instruction share per address space (ASID), stacked — the interleaving
   of traced processes over the run.

``devio_queue``
   Disk-I/O request activity.  Dual pane: peak outstanding requests
   (queue depth) on top; bytes issued per window, split read/write, on
   the bottom.

``devio_latency``
   Histogram of each disk request's STOP−START distance in CP
   instructions — the positional cost of a request, log-bucketed.

``devio_lba``
   A 2D grid of distinct disk blocks (rows, ascending LBA) against trace
   position, colored read / write / read+write — the disk-access
   locality picture.

``wp_termination``
   Why each wrong-path chain ended, stacked per window: ``completed``
   (ran to the recorded end), ``fault stop``, ``translation stop``, and
   ``no fetch`` (the excursion's first target was never realizable).

``ws_divergence``
   Distinct virtual pages vs distinct physical pages live within a
   sliding ``--ws-window``.  A virtual count above the physical count
   exposes aliasing; a physical count trailing virtual growth exposes
   lazily-backed regions.

``translation_churn``
   Virtual→physical remaps (an already-translated page observed with a
   different frame) and first translations, per 1 000 CP instructions.

``pagemap``
   A 2D page-occupancy canvas: virtual pages (rows, first-touch order)
   against trace position, each cell colored by the ASID that touched
   the page there, with cells outlined where the page's physical
   backing changed since its previous observation.  This is the
   address-space evolution picture — process interleave, working-set
   phase changes, and physical remapping in one raster.  ``pagemap``
   and ``devio_lba`` render through a dedicated grid emitter; they are
   per-trace views and are skipped in aggregate mode, and ``--csv``
   (which serialises chart series) does not apply to them.

What each metric needs from the trace
-------------------------------------

The capture flags a trace was produced with determine which metrics it can
drive:

* **Addresses are always recorded.**  ``memdata`` gates the load/store
  *values*, not the addresses, so the address-driven metrics — ``mem_pat``,
  ``cache_miss``, ``working_set``, ``reuse_distance`` — work on any trace,
  including a correct-path-only (``wp=0,memdata=0``) one.
* **Wrong-path metrics need a wrong-path trace.**  ``wp_insns``,
  ``wp_memops``, and ``wp_divergence`` require the speculative chain
  (``wp=1``).  On a trace without it they have nothing to plot.
* **The dual-pane wrong-path panes follow the same rule.**  On a
  correct-path-only trace the WP / pollution pane of ``branch_dir``,
  ``mem_pat``, ``branch_mpki``, ``btb_miss``, and ``cache_miss`` is simply
  empty; the correct-path pane is unaffected.
* **Physical-page metrics need ``physaddr=1``.**  ``ws_divergence``,
  ``translation_churn``, and ``pagemap`` read the per-memop physical-page
  records, present only on system-mode traces captured with
  ``physaddr=1``; without them these metrics are dropped from the
  all-metrics pass.
* **Disk-I/O metrics need DEVIO records.**  ``devio_queue``,
  ``devio_latency``, and ``devio_lba`` consume the disk-I/O records a
  system-mode trace carries when ``devio`` tracing is active; a trace
  that never advertised them drops these metrics from the all-metrics
  pass.  ``wp_termination`` follows the wrong-path rule above.

The warmup marker
-----------------

When a trace records a warmup→simulation boundary (the header's
``warmup_end_trace_insn_idx``; see :doc:`format`), the instruction-window
charts draw it as a dashed vertical rule labelled *end of warmup*, so the
portion of the trace that precedes the SimPoint region of interest is
visible at a glance.  Traces with no warmup configured, or whose warmup
boundary was never crossed, carry no marker.

Model-parameter options
------------------------

.. index::
   single: --history
   single: --btb-entries
   single: --cache-assoc
   single: --rob-size
   single: --ws-window

Each predictor / cache / dataflow metric exposes the knobs of the model it
drives; a swept option draws one chart line per value.

``--history=L,…``
   gshare history lengths for ``branch_mpki`` / ``wp_insns`` / ``wp_memops``
   (``0`` is a pure bimodal predictor).  ``--pht-bits`` sets the pattern
   table size.
``--btb-entries=N,…``
   BTB sizes for ``btb_miss``.
``--cache-block-size`` / ``--cache-sets`` / ``--cache-assoc=A,…`` / ``--cache-policy``
   Geometry and replacement policy of the ``cache_miss`` model; the cache
   size for a line is ``block × sets × assoc``.
``--ws-window=N``
   Sliding-window size for ``working_set``.
``--rob-size=N``
   Reorder-buffer window for ``dep_depth`` / ``ilp``.
``--top-k=N``
   Number of named layers before ``other`` for ``gen_op`` / ``gen_reg``.
``--warmup-bins=N``
   Leading bins excluded from y-axis scaling (predictor / cache warm-up)
   and drawn under a faint overlay, so an untrained transient does not
   dominate the vertical range.  This is the model's warm-up, distinct from
   the trace's own ``warmup_end_trace_insn_idx`` boundary above.

Aggregate mode
--------------

.. index::
   single: aggregate mode
   single: composition plot
   single: --aggregate
   single: --weights

A SimPoint sweep of one program yields several traces, each a weighted
sample of whole-program execution (the header's ``simpoint_weight``).
Passing more than one trace — or ``--aggregate`` explicitly — combines them
into a single representative chart for the program:

.. code-block:: console

   $ build/contrib/plugins/cst_visualize --aggregate --name mcf \
         -m branch_dir -o mcf__branch_dir.svg sweep/mcf-*.cst

Traces are processed one at a time, so peak memory stays at roughly one
trace's working set regardless of how many are combined.  The
``simpoint_weight`` of each trace sets its contribution; ``--weights``
overrides them (in command-line order) and an all-zero or absent set falls
back to an even split.  ``--name`` labels the program in the chart titles.

Two shapes of aggregation match the two shapes of chart:

Composition montage
   Instruction-window charts become a left-to-right montage of per-trace
   segments, ordered by the trace's ``start_insn`` so the chart reads as
   the program executing.  Each segment's width is proportional to its
   weight, and a solid separator divides one simpoint from the next.  Only
   the **post-warmup** region of each trace is plotted — the warmup is not
   part of the SimPoint region — so the chart shows the simulation regions
   composed in weighted proportion, with no warmup rule.  Each segment is
   decoded at a resolution proportional to its weight, so the data-point
   density is uniform across the montage rather than a wide high-weight
   segment appearing coarser than a narrow one.

Weighted distribution
   The histogram charts combine into a single distribution: each trace's
   histogram is normalised and contributed in proportion to its weight, and
   the bars are stacked per simpoint in distinct hues so the composition of
   the overall shape — which simpoints contribute which features — is
   visible.

A series is matched across traces by label, so its colour is consistent
across every segment and the legend.  For ``gen_op`` / ``gen_reg`` the
per-trace top-K sets are reconciled into a single program-wide top-K by
aggregate weight.

Colours are assigned so that the most visually distinct hues land on the
most common categories while a given category keeps the *same* colour in
every plot.  Each category breakdown pins its categories to fixed palette
slots by identity, not by per-plot rank — colouring by magnitude would let
a category's colour drift from one plot to the next and make it hard to
track across the montage.  ``branch_dir`` pins each branch class by name
(the conditional taken/not-taken pair, then jumps, returns and calls);
``gen_op`` pins the common opcodes (loads, stores, moves, the integer ALU
and control ops) to the vivid head of the palette by a fixed frequency
priority, with rarer opcodes falling back to a stable name hash;
``gen_reg`` maps each register class (GPR / VEC / FPR / SP) to a palette
band and the index within the class to an offset; ``mem_pat`` uses four
fixed colours.  The ``other`` fold is always grey.  The parameter-sweep
line charts (``branch_mpki``, ``btb_miss``, ``cache_miss``,
``wp_divergence``, ``working_set``) keep their fixed per-series colours.
In an aggregate (composition) plot a series reuses the colour it has in
the single-trace plot, so a history length, cache associativity or class
looks the same whether viewed alone or in the montage.

Secondary Y axis
   A line chart whose series span very different magnitudes can give one
   series its own right-hand axis so neither is squashed flat.
   ``working_set`` uses this: cumulative unique cache lines scale against
   the left axis and 4 KiB pages against the right, with each axis (ticks
   and title) tinted to match its line.  The right axis is drawn only
   when a plan declares one, so every other chart is unchanged.
