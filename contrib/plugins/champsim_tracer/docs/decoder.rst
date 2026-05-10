Decoder and audit tools
=======================

Two offline consumers of a ``.cst`` trace, both C++ binaries built
alongside the plugin.  ``ninja contrib-plugins`` produces them in
``build/contrib/plugins/`` next to the ``.so`` itself.  Neither tool
needs the QEMU plugin runtime — they read the wire format directly
from the file.

* :ref:`cst_decode <decoder-cc>` is the default decoder.  It emits an
  objdump-style disassembly to stdout, with one line per architectural
  instruction.  ``--templates-only`` suppresses the body walk and emits
  one PC-sorted line per static template entry — the analogue of
  ``objdump -d`` over the captured templates.  ``--objdump`` adds a
  side-by-side Capstone disassembly column so the generic-opcode line
  can be cross-checked against ``objdump`` output.

* :ref:`cst_audit <audit-cc>` prints a byte-budget breakdown of
  where bytes go (header, templates, CP body, WP body, field-delta
  records, ...).  Use it when tuning trace size or diagnosing where
  unexpected bytes accumulated.

.. _decoder-cc:

cst_decode
----------

.. index::
   single: cst_decode
   single: --templates-only
   single: --objdump

Built by the same ``ninja contrib-plugins`` invocation that builds
the plugin shared object.  Lands in
``build/contrib/plugins/cst_decode``.

.. code-block:: console

   $ build/contrib/plugins/cst_decode trace.cst > trace.disasm
   $ build/contrib/plugins/cst_decode --templates-only trace.cst > trace.t.disasm
   $ build/contrib/plugins/cst_decode --objdump trace.cst > trace.objdump.disasm

Output format
~~~~~~~~~~~~~

One architectural instruction per line, modelled after ``objdump -d``:

.. code-block:: text

   0x7b559c7da96f <_start+0xf>: 48 8d 1d 7d ff ff ff   lea     %ip -> %gp11[0x7b559c7da8f9]
   0x7b559c7da976 <_start+0x16>: 31 ed                  xor     %gp5 -> %gp5[0x0], %flags[0x0]
   0x7b559c7da978 <_start+0x18>: e9 16 00 00 00         jmp     %ip -> %ip[0x0]  # 0x7b559c7da993 <_start+0x33>

Columns are PC (12 hex digits), an optional
``<symbol+offset>`` annotation when the captured template named the
TB's owning symbol, the raw instruction bytes from the template, the
generic-opcode mnemonic (``add``/``fmul``/``jmp``/...), and the
operand list in a fake AT&T syntax: register references print as
``%gp0`` / ``%flags`` / ``%ip``, immediates as ``$0x...``, and
destinations are separated from sources by ``->`` so each side of a
read-modify-write is visible at a glance.

The branch-mnemonic flavour (``jmp`` / ``jcc`` / ``jmpr`` / ``ret``
/ ``syscall``) comes from the trace's own ``branch_type`` encoding
map — looked up by the wire-format integer id and matched against
the stable string name — rather than a compile-time enum.  Same for
register and opcode names: the decoder's only source of truth is
the encoding map the writer stamped into the trace header.

Captured per-instruction data is folded into the operand line:

* ``%dst[<value>]`` — destination register post-execution snapshot
  (when ``regdata=1`` was set during capture).
* ``ld(<addr>)=<value>`` / ``st(<addr>)=<value>`` — memory operation
  effective address with the loaded / stored value (when
  ``memdata=1``) or just the address (when ``memdata=0``).
* ``# <target> <symbol+offset>`` trailing comment — branch target
  resolved from the captured ``REG_IP`` snapshot, with the matching
  symbol name when known.  Conditional branches print
  ``# taken=<target>`` so the predicted vs. actual side is visible.

Basic-block boundaries are marked with a single comment line
``# bb <id> tid=<n> [wp]`` so that grepping for a thread or for WP
chains is one regex.  Wrong-path entries get a ``[wp]`` tag on
their boundary marker; the per-instruction lines themselves are
identical in shape.

``--templates-only``
   Skip the body stream entirely and emit exactly one line per
   static template instruction, sorted by PC.  No basic-block
   boundary markers, no per-execution dynamic values — just the
   captured architectural shape.  This is the analogue of running
   ``objdump -d`` over the binary, restricted to PCs that the
   guest actually executed during the trace.

``--objdump``
   Add a side-by-side Capstone-disassembly column to each printed
   line so the generic-opcode rendering can be cross-checked
   against the canonical ISA mnemonic.  Combines with
   ``--templates-only`` (templates side-by-side with Capstone) and
   with the default body walk (per-execution lines side-by-side
   with Capstone, but only the static template half is shown on
   the Capstone side — ``objdump`` has no notion of the captured
   dynamic values).  Capstone is taken from the bundled
   ``subprojects/capstone`` so both sides come from the same
   build the plugin links against.

.. _audit-cc:

cst_audit
---------

.. index::
   single: cst_audit
   single: byte budget

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

Validating a trace
------------------

A ``.cst`` file is well-formed if all of the following hold; the
two C++ tools collectively check every one:

1. **The trailer magic matches the header magic.**
   ``cst_decode`` checks this first; mismatch is a fatal error.
2. **The body's offset and length match the trailer's offsets and
   the header's parsed length.**  ``cst_decode`` raises
   ``header/body offset mismatch`` if not.
3. **The body's footer ENTRY count matches the body walker's
   observation.**  ``cst_decode`` raises
   ``footer entry-count mismatch`` if not.
4. **Every IFRAME (when present) reproduces the same per-entry
   shape as its preceding ENTRY.**  See "IFRAME validation"
   below.
5. **Every section's byte budget rolls up to the file size.**
   ``cst_audit`` verifies this — the printed top-level totals
   (HEADER + TEMPLATES + BODY + TRAILER) sum to ``FILE`` exactly.
   A negative line item or a non-100% rollup is a writer bug.

The recommended validation workflow:

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
   FILE  ...  100.00%       # totals must sum to 100%

   $ build/contrib/plugins/cst_decode trace.cst > /dev/null
   # exit status 0 means the body walker accepted every record

The combination is a cheap end-to-end correctness check: the audit
sums all bytes, and the decoder replays the body's delta stream
end-to-end.

IFRAME validation
~~~~~~~~~~~~~~~~~

.. index::
   single: IFRAME validation
   single: BODY_TAG_IFRAME

When a trace was produced with ``iframe_rate=N`` the writer follows
selected ``BODY_TAG_ENTRY`` records with a redundant ``BODY_TAG_IFRAME``
record carrying the same payload encoded against template-default
baselines (so every value is absolute).  ``cst_decode`` transparently
walks each IFRAME against fresh empty overlays and the body walker
verifies its dyn-param and reg-snap counts match the preceding ENTRY;
mismatches raise an error.  IFRAMEs are not surfaced as separate
``BODY_TAG_ENTRY`` records — ``cst_decode`` reports a body-entry
count that matches the writer's ``num_entries`` footer field.

When you want maximum confidence in a fresh trace (e.g. before
checking it into a paper's artifact repository), produce it with
``iframe_rate=10000`` (every 10000th observation gets a
verification record) and decode it with ``cst_decode`` — the
decoder will fail loudly if any IFRAME's recorded view doesn't
match its delta replay's reconstruction of the matching ENTRY.
Drop the IFRAME flag once you've gotten a clean decode, and the
production trace is byte-identical to one produced without IFRAME
generation.

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
