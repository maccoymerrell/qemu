ChampSim Tracer
===============

ChampSim Tracer is a QEMU TCG plugin that records correct-path and
speculative wrong-path basic-block traces in the ``.cst`` binary
format.  The output is intended for cache and branch-predictor
research — most directly, ChampSim — but the format itself is
independent of any one consumer.

The tracer runs against any QEMU user-mode target QEMU has Capstone
support for (currently x86_64, aarch64, riscv64, mipsel) and writes a
single binary stream describing:

* the basic-block schemas the program executed (templates),
* the dynamic instances of those blocks the CPU stepped through (CP),
* the wrong-path basic blocks speculation would have stepped through if
  each branch had resolved the other way (WP), bounded by a configurable
  depth budget,
* per-instance memory operations (addresses, optional values) and
  optional per-source-register pre-instruction snapshots.

The companion C++ tools (``cst_decode``, ``cst_audit``, built next
to the plugin shared object) read the binary trace and either emit a
disassembly-style text dump or print a byte-budget breakdown of
where bytes go.

.. toctree::
   :maxdepth: 2
   :caption: Using the tracer

   quickstart
   decoder

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
