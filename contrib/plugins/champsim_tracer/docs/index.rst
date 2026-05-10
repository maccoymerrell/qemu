ChampSim Tracer
===============

ChampSim Tracer is a QEMU TCG plugin that records execution traces
of user-mode binaries for cache-, branch-, and prefetcher-research.
It runs the workload under QEMU's user-mode emulator and writes a
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

What it's good for
------------------

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
  issue, BTB, and prefetcher models.

The tracer is not a cycle-accurate timing model and does not see
inside the kernel — it captures *what* executed at user level, not
*when* the hardware would issue it.  See :doc:`limitations` for the
full list of out-of-scope categories.

Supported guest ISAs: x86_64, aarch64, riscv64, mipsel.  Per-ISA
extension coverage is summarized in :doc:`reference`.

The companion C++ tools (``cst_decode``, ``cst_audit``, built next
to the plugin shared object) read the binary trace and either emit a
disassembly-style text dump or print a byte-budget breakdown of
where bytes go.

License: GPL-2.0-or-later, the same as upstream QEMU.  Plugin
source headers each carry the full SPDX line.  If you use the
tracer in published research, please cite the QEMU project and
note that ChampSim Tracer is a contributed plugin distributed
through QEMU's ``contrib/plugins`` tree.

.. toctree::
   :maxdepth: 2
   :caption: Using the tracer

   concepts
   quickstart
   decoder
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

Indices and tables
==================

* :ref:`genindex` — alphabetical index of config flags, wire-format
  tags, and other terms cross-referenced from the prose.
* :ref:`search` — full-text search across the rendered docs.
