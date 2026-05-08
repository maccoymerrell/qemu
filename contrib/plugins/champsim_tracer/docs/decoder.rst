Decoder and audit tools
=======================

Two offline consumers of a ``.cst`` trace, both C++ binaries built
alongside the plugin.  ``ninja contrib-plugins`` produces them in
``build/contrib/plugins/`` next to the ``.so`` itself.  Neither tool
needs the QEMU plugin runtime — they read the wire format directly
from the file.

* :ref:`cst_decode <decoder-cc>` is the default decoder.  It emits a
  greppable objdump-style disassembly to stdout; pass
  ``--format=legacy`` to get the older block-formatted output that
  diff-driven scripts (notably wptrace_genval) consume.

* :ref:`cst_audit <audit-cc>` prints a byte-budget breakdown of
  where bytes go (header, templates, CP body, WP body, field-delta
  records, ...).  Use it when tuning trace size or diagnosing where
  unexpected bytes accumulated.

.. _decoder-cc:

cst_decode
----------

Built by the same ``ninja contrib-plugins`` invocation that builds
the plugin shared object.  Lands in
``build/contrib/plugins/cst_decode``.

.. code-block:: console

   $ build/contrib/plugins/cst_decode trace.cst > trace.disasm
   $ build/contrib/plugins/cst_decode --format=legacy trace.cst > trace.txt

Two output formats:

``--format=disasm`` (default)
   objdump-style, one architectural instruction per line.  Format:

   .. code-block:: text

      0x7b559c7da96f: GEN_OP_LEA   REG_GPR11 <- REG_IP   ; tid=0 bb=98 REG_GPR11=0x7b559c7da8f9
      0x7b559c7da976: GEN_OP_XOR   REG_GPR5,REG_FLAGS <- REG_GPR5   ; tid=0 bb=98 REG_GPR5=0x0 REG_FLAGS=0x0
      0x7b559c7da978: GEN_OP_BRANCH REG_IP <- REG_IP,IMM(0x7b559c7da993)  ; tid=0 bb=98 br=BRANCH_DIRECT_JUMP REG_IP=0x0

   Each line is self-contained: PC, opcode mnemonic (generic),
   destination registers, source registers, immediate (when
   present), and a trailing ``; metadata`` comment carrying the
   thread id, basic-block id, branch type, sync hint, memory
   operations (with effective addresses + optional data), and
   destination register writes (post-execution snapshot).  Basic-
   block boundaries are marked with a ``; ----- BB <id> entry pc=
   ... -----`` separator; wrong-path chains use a ``; ..... wp[k]
   BB <id> ...`` separator.

   Designed for ``grep``: ``grep 'br=BRANCH_COND_DIRECT'``,
   ``grep 'st@0x7fff'``, ``grep 'bb=42'`` all produce useful
   results.

``--format=legacy``
   Block-formatted: META / ENCODINGS / TEMPLATES / BODY sections
   with one ENTRY block per body record.  Stable, machine-parseable;
   wptrace_genval's validator runs ``cst_decode --format=legacy``
   under the hood and parses its output back into Python objects.

.. _audit-cc:

cst_audit
---------

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst

Prints a byte-budget table covering top-level sections, body
breakdown, field-delta record breakdown, and entry / insn totals.
Hands you a hard byte count (every byte produced by the writer is
counted exactly once and the section totals add up to the file
size), so the workflow when tuning trace size is:

1. Run ``cst_audit`` on a baseline trace.
2. Toggle a writer flag (``wp_memdata=0``, ``wp_regdata=0``,
   ``memdata=0``).
3. Re-run.  A flag that pays off shows up as a line item shrinking
   by an order of magnitude.

Sample output:

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
   FILE                                     12.34 MiB  100.00%

   === TOP-LEVEL SECTIONS ===
     HEADER                                  6.18 KiB    0.05%
     TEMPLATES                              412.30 KiB    3.27%  [    3,405 tmpl, avg  104.6 B]
     BODY                                    11.94 MiB   96.66%
     TRAILER                                      64 B    0.00%

   === BODY BREAKDOWN (11.94 MiB) ===
     CP entry framing                        71.78 KiB    0.59%  [   35,857 entry, avg    2.0 B]
     CP field-delta section                 185.99 KiB    1.52%  [   35,857 entry, avg    5.3 B]
     ...
     IFRAME records (validation redundancy)  80.34 KiB    0.66%  [      388 iframe, avg  212.0 B]

The ``IFRAME records`` line appears only on traces produced with
``iframe_rate>0``; those bytes are pure validation overhead and
disappear when the feature is off.

Format-version handling
-----------------------

Both tools read v1.7, v1.8, and v1.9 traces.  They pick the right
code path off the trailer's magic byte:

.. code-block:: text

   0x17545343 → v1.7  (legacy; per-entry sub-sections)
   0x18545343 → v1.8  (unified delta stream; per-chain WP overlay reset)
   0x19545343 → v1.9  (unified delta stream; persistent WP overlay)

If you bump the wire format (cf. :doc:`extending`), the new magic
needs a corresponding ``MAGIC_V*`` constant in
``contrib/plugins/champsim_tracer/tools/cst_common.h`` and the
parser branches need updating.  Keeping older readers compiled in
is by design — debugging cross-version traces is a common need.

IFRAME validation
-----------------

When a trace was produced with ``iframe_rate=N`` the writer follows
selected ``BODY_TAG_ENTRY`` records with a redundant ``BODY_TAG_IFRAME``
record carrying the same payload encoded against template-default
baselines (so every value is absolute).  ``cst_decode`` transparently
walks each IFRAME against fresh empty overlays and the body walker
verifies its dyn-param and reg-snap counts match the preceding ENTRY;
mismatches raise an error.  IFRAMEs are not surfaced as separate
``BODY_TAG_ENTRY`` records — ``cst_decode`` reports a body-entry
count that matches the writer's ``num_entries`` footer field.

mnemonic survey / audit
-----------------------

Two helpers tied to the disassembly classification step rather than
the wire format:

* ``champsim_tracer_mnemonic_survey.py`` walks a workload, records
  every Capstone mnemonic it sees, and prints frequency counts.
  Useful when adding ISA support: it tells you which mnemonics need
  rows in ``champsim_tracer_mnemonic_tables.c``.

* ``champsim_tracer_mnemonic_audit.py`` diffs the union of seen
  mnemonics against the static classification table and reports any
  unclassified ones.  Run after adding a new opcode or ISA to confirm
  the table covers the workload.

Both run against an existing trace and don't require a fresh QEMU
invocation.
