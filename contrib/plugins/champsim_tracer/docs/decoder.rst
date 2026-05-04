Decoder and audit tools
=======================

The Python files alongside the plugin source give two ways to consume
a ``.cst`` trace:

* :ref:`champsim_tracer_decode.py <decoder-api>` is a library + CLI
  that yields structured records (templates, body entries, dynamic
  fields).  Use this when you want to *do something* with the trace —
  feed it into a simulator, validate per-instruction invariants, or
  diff two traces.

* :ref:`cst_audit.py <audit-tool>` is a CLI that prints a byte-budget
  breakdown of where bytes go (header, templates, CP body, WP body,
  field-delta records, ...).  Use this when tuning trace size or
  diagnosing where unexpected bytes accumulated.

Both scripts read directly from the canonical wire format described
in :doc:`/format` and require no plugin build artifact.

.. _decoder-api:

champsim_tracer_decode.py
-------------------------

The decoder is a single self-contained module.  It can be imported as
a library or run as ``python3 champsim_tracer_decode.py <trace.cst>``.

CLI
~~~

.. code-block:: console

   $ python3 champsim_tracer_decode.py trace.cst.cst > trace.txt

Renders a human-readable text dump of the trace: one line per template
in the templates section, one block per body entry showing CP and WP
sub-records with their dynamic field values resolved through the
encoding maps.  Useful for diffing two traces (``diff -u``) when you
suspect a bytes-on-wire difference but can't see it in ``cst_audit``.

Library API
~~~~~~~~~~~

The public entry point is a single function — the decoder reads the
whole trace into memory and returns three lists in one call.  There
is no incremental / streaming API today; if you need one, the
function's body is a straight-line read against ``ByteReader`` and
can be adapted.

.. py:function:: decode_champsim_tracer(bin_path)

   Reads the trailer, header, templates, and entire body of
   ``bin_path`` and returns a 3-tuple ``(meta, templates, entries)``.

   :param bin_path: ``pathlib.Path`` to a ``.cst`` trace.
   :returns: ``tuple[dict, list[dict], list[dict]]``
   :raises ValueError: when the trailer magic doesn't match a known
       wire-format version, or when section offsets in the trailer
       don't agree with the header / body sizes the decoder produced.

   ``meta`` carries header fields and the resolved encoding maps the
   decoder will refer to (``opcode_names``, ``branch_names``,
   ``reg_names``, ``field_id_names``, ``sync_hint_names``, plus
   feature flags and identifying strings from the header).

   ``templates`` is a list of dicts shaped like
   :py:func:`_decode_template_record` builds:

   .. code-block:: python

      {
          "template_id":     int,
          "start_pc":        int,
          "n_insns":         int,
          "fall_through_pc": int,
          "symbol_name":     str,
          "insns": [
              {
                  "pc":                 int,
                  "opcode":             int,   # GenericOpcode value
                  "branch_type":        int,
                  "branch_conditional": bool,
                  "src_regs":           list[int],
                  "dst_regs":           list[int],
                  "imm":                int | None,
                  "sync_hint":          int,
                  "n_loads":            int,   # template default; usually 0
                  "n_stores":           int,
                  "raw_bytes":          bytes,
              },
              ...
          ],
      }

   ``entries`` is a list of dicts, each describing one body entry
   (one CP basic-block instance plus its WP chain):

   .. code-block:: python

      {
          "seq_num":         int,
          "template_id":     int,
          "thread_id":       int,
          "thread_switched": bool,             # true on the first
                                               # entry after a
                                               # BODY_TAG_THREAD_SWITCH
          "dyn_params":      list[DynParam],   # CP-side memops
          "reg_snaps":       list[dict],       # CP-side reg snapshots
          "wp_entries": [
              {
                  "index":                   int,
                  "template_id":             int,
                  "n_insns":                 int,    # from template
                  "dyn_params":              list[DynParam],
                  "reg_snaps":               list[dict],
                  "fault":                   bool,
                  "translation_unavailable": bool,
                  "fault_insn_index":        int | None,
              },
              ...
          ],
      }

.. py:class:: DynParam

   Dataclass for one decoded memop record.  Always built with
   ``type_name`` set to either ``"load"`` or ``"store"``; register
   snapshots are not represented as ``DynParam`` (see
   ``reg_snaps`` below).

   :ivar type_name: ``"load"`` or ``"store"``.
   :ivar value:     Memory virtual address.
   :ivar data_size: Access width in bytes (zero when value capture is
       off).
   :ivar data:      Full 512-bit payload masked to the trace's
       ``MEM_DATA_BIT_MASK``.
   :ivar data_lo:   Low 64 bits of ``data`` (convenience).
   :ivar data_hi:   Bits 64..127 of ``data`` (convenience).
   :ivar insn_index: Position within the BB template (0-based).

   The ``reg_snaps`` lists in entries / WP entries hold dicts, not
   ``DynParam`` instances:

   .. code-block:: python

      {
          "insn_index":     int,
          "kind":           "src",      # only "src" today
          "operand_index":  int,        # 0..n_src_regs-1 of that insn
          "reg_id":         int,        # GenericRegId
          "value":          int,        # masked-to-trace-width
          "lo":             int,        # low 64
          "hi":             int,        # bits 64..127
      }

Format-version handling
~~~~~~~~~~~~~~~~~~~~~~~

The decoder reads v1.7, v1.8, and v1.9 simultaneously.  It picks the
right code path off the trailer's magic byte:

.. code-block:: text

   0x17545343 → v1.7  (legacy; per-entry sub-sections)
   0x18545343 → v1.8  (unified delta stream; per-chain WP overlay reset)
   0x19545343 → v1.9  (unified delta stream; persistent WP overlay)

If you bump the wire format (cf. :doc:`extending`), the new magic
needs a corresponding ``CST_MAGIC_V*`` constant near the top of
``champsim_tracer_decode.py`` and the ``decode_champsim_tracer``
dispatch needs the new branch.  Keeping older readers in the same
module is by design — debugging cross-version traces is a common
need.

.. _audit-tool:

cst_audit.py
------------

A focused diagnostic.  Prints how many bytes each part of the trace
consumed and what the largest line items inside each part are.

.. code-block:: console

   $ python3 cst_audit.py trace.cst.cst
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

The numbers are a hard byte count — every byte produced by the writer
is counted exactly once and the section totals add up to the file
size.  When tuning trace size, the workflow is:

1. Run ``cst_audit.py`` on a baseline trace.
2. Toggle a writer flag (``wp_memdata=0``, ``wp_regdata=0``,
   ``memdata=0``).
3. Re-run.  A flag that pays off shows up as a line item shrinking by
   an order of magnitude.

The audit exposes its own ``audit()`` and ``report()`` functions for
programmatic use, but the typical pattern is the CLI.

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
