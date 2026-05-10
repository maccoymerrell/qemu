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

   Companion pages: :doc:`reference` for the symbolic ID tables that
   the format references (opcodes, branch types, register IDs, field
   IDs); :doc:`decoder` for the Python reader that consumes this
   format.

.. include:: ../champsim_tracer_format.md
   :parser: myst_parser.sphinx_
