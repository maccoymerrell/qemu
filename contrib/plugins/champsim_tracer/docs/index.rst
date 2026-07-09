ChampSim Tracer
===============

ChampSim Tracer is a QEMU TCG plugin that records execution traces
for micro-architectural research.  It runs the workload under
QEMU's user-mode emulator — or pins a chosen process inside a
full-system guest via a marker-driven window — and writes a
``.cst`` binary file containing both the architectural correct-path
execution and a per-branch *wrong-path* shadow that models what a
mispredicting CPU would have done.

The trace's structure has two halves: a deduplicated dictionary of
every static basic block the program executed (the *templates*
section), and a per-invocation stream of dynamic events keyed back
into that dictionary (the *body*).  Per-invocation events include
every load/store virtual address, optional load/store values,
optional post-execution destination-register snapshots, and the
bounded speculative chain attached at each branch.  See
:doc:`concepts` for the qualitative picture and :doc:`format` for
the byte-level wire format.

**What it's good for:**

* **Cache simulation** — drop the address stream into a cache model
  to measure miss rates, study replacement policies, evaluate
  prefetchers.  The wrong-path stream lets you quantify cache
  pollution from speculation.
* **Branch prediction** — every branch in the trace has its actual
  outcome plus the alternate path a mispredict would have entered,
  bounded by ``wpdepth`` instructions.
* **Prefetcher evaluation** — software prefetch hints, addressed
  cache-line ops, and TLB-shootdown ops all surface as synthetic
  loads with computed effective addresses, alongside the workload's
  real demand stream.
* **Value prediction** — pass ``regdata=1,memdata=1`` and the trace
  records destination-register and memory values post-execution.
* **Microarchitectural design-space exploration** — ChampSim and
  comparable simulators consume the trace to drive out-of-order
  issue, BTB, branch predictor, and prefetcher models.

The tracer contains no timing information — it captures *what*
executed (*commit-order*), not when the hardware would issue it
(*timing*).  User-mode traces stop at the system-call boundary;
system-mode traces additionally carry the pinned process's
synchronous kernel excursions (syscalls and fault handlers), tagged
so consumers can model or filter them.  See :doc:`limitations` for
the full list of out-of-scope categories.

Supported guest ISAs: x86_64, aarch64, riscv64, mipsel.  Per-ISA
extension coverage is summarized in :doc:`reference`.

The companion C++ tools, built next to the plugin shared object, read
the binary trace directly: ``cst_decode`` emits a disassembly-style
text dump, ``cst_audit`` prints a byte-budget breakdown of where bytes
go, and ``cst_visualize`` renders a metric over the run as an SVG chart
(branch behaviour, memory-access patterns, instruction mix, dependency
depth, speculative-pollution cost), with an aggregate mode that composes
a SimPoint sweep into one weighted whole-program view.

A Python harness, :doc:`validator`, generates self-checking
workloads, runs them through the plugin, and validates the resulting
trace against ~25 named correctness checks (encoding-map
completeness, IFRAME / REGFILE / sync-hint / WP-event consistency,
metaflags / regdata semantic reconstruction, multi-thread and
multi-segment isolation, …).  It is the primary regression suite for
tracer changes.

If you use the tracer in published research, please cite the QEMU project
as well as the tracer itself (an upcoming publication).

.. toctree::
   :maxdepth: 2
   :caption: Using the tracer

   concepts
   quickstart
   decoder
   visualizer
   validator
   troubleshooting
   limitations

.. toctree::
   :maxdepth: 2
   :caption: Internals

   architecture
   qemu_modifications
   extending

.. toctree::
   :maxdepth: 2
   :caption: Wire format

   format
   reference

.. toctree::
   :maxdepth: 1
   :caption: Appendices

   _generated/encoding_tables

.. only:: html

   Indices and tables
   ==================

   * :ref:`genindex` — alphabetical index of config flags, wire-format
     tags, and other terms cross-referenced from the prose.
   * :ref:`search` — full-text search across the rendered docs.

.. only:: latex

   The alphabetical index follows this chapter — see the back of the
   document for it.  Full-text search is HTML-only.
