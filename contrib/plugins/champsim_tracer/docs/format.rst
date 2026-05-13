Wire format
===========

.. index::
   single: wire format
   single: BODY_TAG_ENTRY
   single: BODY_TAG_END
   single: BODY_TAG_THREAD_SWITCH
   single: BODY_TAG_IFRAME
   single: BODY_TAG_REGFILE
   single: FieldStateTable
   single: encoding map
   single: trailer
   single: header
   single: templates section

.. note::

   The canonical wire-format spec is the markdown file
   ``champsim_tracer_format.md`` next to ``champsim_tracer_output.cc``.
   It is rendered below verbatim.  When the writer changes, that file
   is the one that needs updating; this page just embeds it so the
   site has one document per topic.

   The spec is split into two parts: **Part I — Decoder Recipe** is a
   procedural Step 0 .. Step 7 walkthrough for writing a decoder from
   scratch, and **Part II — Reference** is the byte-level field-by-
   field description for cross-checking specific bits.  Read Part I
   end-to-end when implementing a new consumer; reach for Part II
   when you need exact byte layouts or constant values.

   Companion pages: :doc:`reference` for the symbolic ID tables that
   the format references (opcodes, branch types, register IDs, field
   IDs); :doc:`decoder` for the C++ ``cst_decode`` and ``cst_audit``
   binaries that consume this format.

.. include:: ../champsim_tracer_format.md
   :parser: myst_parser.sphinx_
