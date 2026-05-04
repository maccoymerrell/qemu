Extending the tracer
====================

The most common changes — adding a new generic opcode, a new register
ID, a new branch type, or a new dynamic field on the wire — touch a
small, predictable set of files because of the carve-outs in
``champsim_tracer_generic_ids.h`` and the descriptor-driven design of
``champsim_tracer_output.cc``.

This page walks each scenario.  In every case the high-level rule is
the same: **add the ID at exactly one place in the C-side enum, and
its name at exactly one place in the inline ``*_name`` switch.**
Everything else is sized off the COUNT sentinels.

Adding a generic opcode
-----------------------

Use this when the existing 58-value ``GenericOpcode`` enum doesn't
classify some new instruction class — for example, a new vector-fma
variant, a cryptographic primitive, or a hardware-transactional-memory
op.  The wire format reserves one ``u8`` per insn for the opcode, so
there's room up to 255 entries before the format itself has to change.

1. **Define the ID** in
   ``champsim_tracer_generic_ids.h``: pick the lowest free integer
   inside ``enum GenericOpcode``.  Don't reuse 26 — it's reserved by
   convention for "call-shaped control flow" which we collapse into
   ``GEN_OP_BRANCH``.  The sentinel ``GEN_OP_COUNT`` autoadvances.

   .. code-block:: c

      GEN_OP_AES_ENC = 58,
      GEN_OP_COUNT,

2. **Name the ID** in the same header's ``generic_opcode_name``
   switch.  Keep the case order in lockstep with the enum value order
   for readability — there's no hash table, just a switch:

   .. code-block:: c

      case GEN_OP_AES_ENC:    return "GEN_OP_AES_ENC";

3. **Classify the instruction** in
   ``champsim_tracer_decode.cc``.  This is the only ISA-aware step.
   ``decode_detail_to_generic`` walks the per-ISA Capstone mnemonic
   tables (``insn_classification`` rows in
   ``champsim_tracer_mnemonic_tables.c``) and writes the opcode into
   ``InsnFields.opcode``.  Add a row to whichever ISA(s) implement the
   instruction:

   .. code-block:: c

      { "aesenc",  GEN_OP_AES_ENC, BRANCH_NONE, SYNC_NONE, false, false },

   ``champsim_tracer_mnemonic_audit.py`` is the easiest way to verify
   no ISA's ``insn_classification`` table is missing a Capstone
   mnemonic the workload uses — it diffs the union of mnemonics
   Capstone has emitted on a sample workload against the static table
   and prints the unclassified set.

4. **Update the Python decoder.**  ``OPCODE_NAMES`` in
   ``champsim_tracer_decode.py`` is a flat ``int -> str`` dict; add
   ``58: "AES_ENC"``.  This lets ``cst_audit.py`` pretty-print the new
   opcode even when the trace's encoding-maps section pre-dates its
   addition.

5. **Build and verify.**  The C-side ``static_assert`` in
   ``champsim_tracer.cc`` (``GEN_OP_COUNT <= 256``) keeps the wire
   format from quietly growing past one byte.  After
   ``ninja contrib/plugins/libchampsim_tracer.so`` the new opcode
   appears in the exit-time summary's "Generic opcode breakdown"
   table on workloads that use it.

No format-version bump is needed: existing ``u8`` opcode IDs simply
gain a new legal value.  Old decoders that don't know the new name will
fall back to ``GEN_OP_???`` and still decode the rest of the trace.

Adding a register ID
--------------------

Adding an architectural register that doesn't fit the existing dense
banks (GPR0..63, FPR0..63, VEC0..63, PRED0..31, SEG0..5) or the
special-purpose singletons (SP, FLAGS, IP, LR, FP_REG, ZERO, MATRIX,
SYS, FCSR, VCTRL).

The IDs in ``GenericRegId`` are *not* dense — they leave gaps between
banks deliberately so the dense banks can be hashed by base-relative
offset.  Pick from the unallocated holes (currently 246..249) for a
new singleton, or extend a dense bank cleanly.

1. **Pick an ID** in ``champsim_tracer_generic_ids.h``.  Stay below
   255 so it still fits in a ``uint8_t``.  ``REG_ID_COUNT`` (255) is
   the sentinel — bump it only if you exhaust the space, which forces
   a wire-format bump.

   .. code-block:: c

      REG_NEW_THING = 246,

2. **Name it** in ``generic_reg_name``.  Singletons get a literal
   ``case REG_NEW_THING: return "REG_NEW_THING";`` block.  A new
   dense bank gets a range check that snprintfs into the thread-local
   buffer:

   .. code-block:: c

      } else if (id >= REG_NEW_BANK0 && id < REG_NEW_BANK0 + 16) {
          snprintf(buf, sizeof(buf), "REG_NEW_BANK%u", id - REG_NEW_BANK0);

3. **Map ISA registers to it** in
   ``champsim_tracer_mnemonic_tables.c``.  Each ISA's
   ``reg_classification`` table maps Capstone register names to a
   ``GenericRegId``.  Add the entry for every ISA that exposes the new
   register:

   .. code-block:: c

      { "newreg", REG_NEW_THING },

   The ``champsim_tracer_mnemonic_survey.py`` helper prints
   per-Capstone-name hit counts on a workload, which is the easiest
   way to discover what name the disassembler is actually emitting.

4. **Mirror the addition in the decoder.**  ``build_reg_names`` in
   ``champsim_tracer_decode.py`` constructs the canonical
   ``REG_NAMES_DEFAULT`` dict.  Add the new singleton or bank entries
   alongside the existing ones.  The trace's encoding-maps section
   carries names from the writer side, so a stale decoder still names
   the register correctly when reading a fresh trace; updating the
   decoder is for back-compat with traces from older plugin builds.

Per-register attribution counters in ``g_stats`` (``cp_src_reg_uses``,
``cp_dst_reg_writes``, ``wp_src_reg_uses``, ``wp_dst_reg_writes``) are
sized by ``REG_ID_COUNT``, so they automatically cover the new ID.

Adding a branch type
--------------------

Use this if some control-flow class isn't captured by the existing
``BRANCH_DIRECT_JUMP`` / ``BRANCH_INDIRECT_JUMP`` / ``BRANCH_RETURN`` /
``BRANCH_SYSCALL_TYPE`` / ``BRANCH_COND_DIRECT`` set — for example, a
predicated branch with a specific microarchitectural flavour, or a
trap-style branch that you want to model differently from a syscall.

1. **Define the ID** in ``champsim_tracer_generic_ids.h``.  The wire
   format encodes branch type as ``u8`` so there is plenty of room.
   ``BRANCH_TYPE_COUNT`` autoadvances.

2. **Name it** in ``branch_type_name``.

3. **Wire ISAs into it** in ``champsim_tracer_mnemonic_tables.c``: the
   ``insn_classification`` row for the relevant mnemonic gets the new
   ``BranchType``.

4. **Teach the WP target resolver** in
   ``champsim_tracer.cc::resolve_wrong_target`` how to choose the WP
   target for the new type.  This is the only piece of code that's
   *not* sized off the enum — it's a switch on branch_type.  Forgetting
   this step results in WP simulation skipping branches of the new
   type (no harm, but no coverage).

5. **Add the name to the decoder's ``BRANCH_NAMES`` dict** in
   ``champsim_tracer_decode.py`` for back-compat with old traces.

Per-branch-type counters and the histogram tables are sized by
``BRANCH_TYPE_COUNT``, so they pick up the new entry automatically.

Adding a dynamic field
----------------------

Dynamic fields are the per-execution observations the wire format
records as deltas against template defaults — memop addresses,
memop data values, source-register snapshots, instruction-encoding
mutations.  Adding a new one is the most invasive change because it
touches the wire format.

The format reserves a contiguous ``u8`` Field-ID space; see
:doc:`/format` for the layout.  Slotted families (load/store
addresses, load/store data, source-reg values) occupy 16-wide ranges;
scalar instruction-mutable fields live in the 0x70..0xFE band; 0xFF
is reserved as an escape.  Unallocated bands are available for new
families.

1. **Pick a band** in ``champsim_tracer.h`` next to the existing
   ``CST_FID_*`` constants.  A scalar gets a single ID; a slotted
   family gets ``CST_FID_NEW_BASE`` plus 16 slots.  Document the
   payload encoding in the same comment.

2. **Define a ``FieldDescriptor``** in
   ``champsim_tracer_output.cc``.  Each field family has a row of
   four callbacks: ``extract`` (reads the current value), ``baseline``
   (current overlay value), ``template_default`` (zero-default for
   first sighting), ``writer`` (encodes one record's payload).  The
   existing rows are heavily commented; copy the closest match and
   adjust.

3. **Optionally feed runtime values** into
   ``BodyEntry`` / ``WPBBEntry`` so the extract callback has somewhere
   to read from.  Loads / stores are recorded by
   ``MemAccessRecorder`` and live in ``BodyEntry::dyn_params``;
   register snapshots come from ``RegSnapCollector`` and live in
   ``BodyEntry::reg_snaps``.  A new family typically wants a parallel
   vector with the field's payloads.

4. **Bump the magic byte** at the top of ``champsim_tracer.h``.  The
   v1.8 → v1.9 transition (persistent WP overlay) is the canonical
   precedent — both the body-stream consumer and the trailer sentinel
   moved from ``0x18545343`` to ``0x19545343``.  Update the
   ``CST_MAGIC`` / ``CST_TRAILER_MAGIC`` constants and the format
   description at the top of the header.

5. **Mirror the field-ID and decoder logic** in
   ``champsim_tracer_decode.py``.  ``FID_*`` constants live near the
   top; new dynamic-field handling typically belongs in
   ``_decode_field_delta_section``.  The Python side already supports
   v1.7 / v1.8 / v1.9 simultaneously by branching on the magic, so
   keep that pattern.

6. **Document the field** under :doc:`/format`.  Existing readers
   tolerate unknown field-IDs (skip with the encoded length), so
   forward-compatibility is OK; reverse-compatibility is what wants
   the explicit schema in the docs.

Adding a SimPoint-style segmentation flag
-----------------------------------------

Easier scenario.  You want a new way to slice a run into segments —
for example, periodic time-based segments, or a trigger from a sync
hint.

1. Add a ``key=value`` plugin option in
   ``champsim_tracer_plugin_config.{h,cc}`` (a setter function, an
   options-table row, and a field on ``PluginConfig``).
2. Plumb the field through to a new manager class alongside
   ``SimPointManager``, exposing the same surface
   (``current() -> SegmentEntry *``, ``advance()``, ``is_active()``).
3. In ``champsim_tracer.cc::vcpu_tb_exec``'s window-management block,
   add a branch that consults the new manager when its option was
   set.  Cf. how SimPoint mode and stop-only mode coexist there
   already.

Verifying changes
-----------------

After any of the above, two scripts give you fast confidence:

* ``cst_audit.py`` decodes a sample trace and verifies every section's
  byte budget rolls up to the file size.  A field-format mistake shows
  up either as a decode error or as the "section overhead" line going
  wildly negative.

* ``champsim_tracer_mnemonic_audit.py`` walks a sample workload and
  reports any Capstone mnemonic with no ``insn_classification`` row,
  flagging silent ``GEN_OP_UNKNOWN`` regressions.
