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

Use this when the existing 61-value ``GenericOpcode`` enum doesn't
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

      GEN_OP_AES_ENC = 61,
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

      { "aesenc",  GEN_OP_AES_ENC, BRANCH_NONE, MF_NONE,
        /*.refine=*/NULL, /*.dep_refine=*/dep_all_to_all },

   ``champsim_tracer_mnemonic_audit.py`` is the easiest way to verify
   no ISA's ``insn_classification`` table is missing a Capstone
   mnemonic the workload uses — it diffs the union of mnemonics
   Capstone has emitted on a sample workload against the static table
   and prints the unclassified set.

4. **Update the generic-id name lookup.**  Both the plugin's writer
   and the offline tools share ``champsim_tracer_generic_ids.h``;
   adding ``GEN_OP_AES_ENC`` to the ``GenericOpcode`` enum and
   ``"AES_ENC"`` to ``generic_opcode_name()``'s switch is enough for
   ``cst_decode`` and ``cst_audit`` to pretty-print the new opcode
   even when the trace's encoding-maps section does not list it.

5. **Build and verify.**  The C-side ``static_assert`` in
   ``champsim_tracer.cc`` (``GEN_OP_COUNT <= 256``) keeps the wire
   format from quietly growing past one byte.  After
   ``ninja contrib/plugins/libchampsim_tracer.so`` the new opcode
   appears in the exit-time summary's "Generic opcode breakdown"
   table on workloads that use it.

Existing ``u8`` opcode IDs simply gain a new legal value.  No
wire-format change is required because the per-trace encoding map
in the header carries the (id, name) pair so any reader that walks
the map picks up the new opcode without a code change.

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
   the count sentinel; the wire stays self-describing through the
   ``reg`` map regardless of which ids are used, so adding ids is not
   a versioned change.  Needing more than 255 ids is the one
   structural limit (it no longer fits ``uint8_t``).

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

4. **Mirror the addition in the generic-id table.**
   ``generic_reg_name`` in ``champsim_tracer_generic_ids.h`` covers
   the canonical name for each ``GenericRegId`` and is consumed by
   both the plugin and the offline tools.  Add the new singleton or
   bank entry alongside the existing ones.  The trace's
   encoding-maps section carries names from the writer side too, so
   an offline tool whose table lacks the new id still resolves it
   when reading a trace that lists it; updating the table covers
   traces whose encoding-maps section does not carry the name.

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

5. **Verify decoders still surface the new type.**  The writer stamps
   the symbolic name into the trace's ``branch_type`` encoding map
   (see :doc:`/format` *Part I, Step 3*), and the C++ ``cst_decode``
   looks branch types up by string at decode time — so a new branch
   id auto-flows through to the decoded view without a tools-side
   rebuild for the wire format itself.  If the new type should also
   render with a short objdump-style mnemonic (``jmp`` / ``jcc`` /
   ``rep`` / ...), add a row to ``branch_mnem_from_name`` in
   ``contrib/plugins/champsim_tracer/tools/cst_decode_main.cc`` —
   otherwise the renderer falls back to a generic ``br`` annotation.

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

4. **Mirror the field-ID handling** in
   ``contrib/plugins/champsim_tracer/tools/cst_decode.cc``.  The
   field-delta walker is where new FIDs need parsing logic; the
   shared ``cst_common.h`` carries the FID_* constants.

5. **Document the field** under :doc:`/format`.  The encoding-map
   "field_id" entry the writer emits is enough for an external
   reader to know the new ID exists; the byte-level layout and
   semantics belong in the wire-format spec.

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
   set.  Cf. how SimPoint mode and stop-only mode coexist there.

Verifying changes
-----------------

After any of the above, two scripts give you fast confidence:

* ``build/contrib/plugins/cst_audit`` decodes a sample trace and
  verifies every section's byte budget rolls up to the file size.
  A field-format mistake shows up either as a decode error or as the
  "section overhead" line going wildly negative.

* ``champsim_tracer_mnemonic_audit.py`` walks a sample workload and
  reports any Capstone mnemonic with no ``insn_classification`` row,
  flagging silent ``GEN_OP_UNKNOWN`` regressions.
