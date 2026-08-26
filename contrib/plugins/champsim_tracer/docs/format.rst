Wire format
===========

.. index::
   single: wire format
   single: BODY_TAG_ENTRY
   single: BODY_TAG_END
   single: BODY_TAG_THREAD_SWITCH
   single: BODY_TAG_ASID_SWITCH
   single: BODY_TAG_DEVIO_START
   single: BODY_TAG_DEVIO_STOP
   single: BODY_TAG_IFRAME
   single: BODY_TAG_REGFILE
   single: FieldStateTable
   single: encoding map
   single: BLOCK_POS
   single: block-level fields
   single: header
   single: templates section

.. note::

   Companion pages: :doc:`reference` for the symbolic ID tables this
   format references (opcodes, branch types, register IDs, field IDs);
   :doc:`decoder` for the ``cst_decode`` and ``cst_audit`` binaries that
   consume it.

This document specifies the on-disk ``.cst`` stream written by
``champsim_tracer_output.cc`` and decoded by ``cst_decode``, and is the
canonical reference for both the format and the tracer's use of it.
The format is in its pre-release epoch, identified by ``CST_MAGIC``
(``0x1E545343``).  See *Format Stability and Conformance* (below) for
what the epoch identifier fixes, the minimum a conformant trace must
carry, and the forward-compatibility rules that govern additive
evolution within the epoch.

All multi-byte fixed-width integers are little-endian. Variable-width
integers use DWARF-style LEB128:

::

   ULEB        unsigned LEB128, value fits in u64
   SLEB        signed LEB128, value fits in i64
   ULEB_WIDE   unsigned LEB128 whose value fits in u512 (8
               little-endian u64 limbs).  Same continuation-bit
               format as ULEB; decoders accumulate into 8 limbs
               instead of one.  Defines the wide-LEB shape that
               SLEB_WIDE is the signed form of.
   SLEB_WIDE   signed LEB128, value fits in i512 (sign extension via
               the high bit of the final byte's 7-bit payload).
               The wide field-delta value in the body stream (memop
               addresses, vector / register data, etc.).
   u8          one byte
   u32         four bytes, little-endian
   u64         eight bytes, little-endian
   f64         eight bytes, little-endian IEEE-754 binary64

Every fixed-width integer/float in this format is little-endian;
the recipe sometimes writes the explicit suffix form (``u32_le``,
``f64_le``) at a field for emphasis — it denotes exactly the same
encoding as the unsuffixed token above.

Strings are length-prefixed UTF-8 byte strings:

::

   string := len:ULEB  bytes[len]

Length-prefixed sections use the same shape:

::

   section := len:ULEB  payload[len]

Throughout the recipe, a field typed ``: section`` is therefore **two
reads**: first the ``len:ULEB`` byte-length prefix, then the ``payload[len]``
bytes.  The step a ``: section`` field cross-references (e.g. "see Step
6.7") describes only the *payload* — the ``len:ULEB`` has already been
consumed by the ``: section`` framing at the use site, exactly as a
``: string`` field reads its ``len:ULEB`` before its bytes.  The two are
distinct: ``len`` is the on-the-wire byte size of the section (what a
reader skips to reach the next one), independent of how many logical
records the payload then declares.

This spec is split into two parts.  **Part I** is a procedural
recipe for a decoder author: each step is "read N bytes, decode as
X, branch on Y."  Following the recipe in order is sufficient to
parse any well-formed ``.cst`` file; values are not interpreted, just
laid out byte-by-byte.  **Part II** is the reference for what each
field *means* semantically (opcode enums, FID semantics, replay
rules, etc.).  Sections in Part II are cross-referenced from the
recipe steps that produce the relevant bytes.

Format Stability and Conformance
--------------------------------

The magic epoch
~~~~~~~~~~~~~~~

``CST_MAGIC`` (``0x1E545343``) identifies the format epoch.  Within an
epoch the layout evolves, but every change is *additive* and leaves
the magic untouched.  Additive evolution needs no magic change because
every numeric domain resolves through the per-trace encoding maps and
body records are self-delimiting, so a reader built to this
specification stays correct across additive changes.  A structurally
breaking change — a different record shape, step order, or
structurally-required field set — bumps ``CST_MAGIC``: the magic is the
format-epoch identifier and that bump is the signal for "not the same
format".

The magic's low three bytes spell ``'C' 'S' 'T'``; its high byte is the
epoch counter.  ``0x1D545343`` is the **previous** epoch, in which a
body entry carried a fixed synchronous-fault trailer, a packed
wrong-path chain header, and a separate wrong-path events section, and
in which one entry always described a whole basic-block invocation.
This epoch replaces all four with block-level field-delta records
(§5.7) and an explicit executed range.  The two are not
interconvertible and a reader MUST reject a magic it does not
implement rather than attempt either: a ``0x1D`` reader handed a
``0x1E`` body desynchronises at the first entry, and — the reason the
epoch had to move rather than extend — a reader that merely *skipped*
the unrecognised range records would stay byte-synchronised while
silently over-claiming executed instructions on every partial entry.

Forward compatibility (normative)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Encoding maps are open.**  A writer MUST emit a map entry for
  every numeric value that appears anywhere in the trace; a value
  with no entry is malformed.  Beyond that the maps are open — a
  reader MUST build them generically (Step 3) and MUST tolerate
  maps, and map entries, it does not recognise (extra ones are not
  an error).  A reader MUST resolve every value it acts on through
  the maps, never by a hard-coded number.
* **Reserved bits are reserved.**  Writers MUST write every
  reserved flag/field bit as 0.  Readers MUST consider only the
  bits they recognise; an unrecognised bit being set is not by
  itself an error.
* **Field-delta records are self-delimiting and skippable.**  Each
  body field-delta record is ``ipos_delta:ULEB, fid:ULEB,
  delta:SLEB_WIDE`` (plus, only for ``CST_FID_EXTENDED``, a trailing
  ``ext_payload:ULEB``).  A reader that does not recognise ``fid`` MUST
  still consume the whole record — the LEB framing fixes its length
  unambiguously — and continue.  This is the format's per-record
  extension point: new observations, per-instruction or block-level
  (§5.7), are added as new field-IDs that older readers skip.  The
  *position* space is not open the same way: a section defines only
  the positions its referenced template has — its instructions plus
  the one block position above them — and a record addressed past
  those is malformed however unrecognised its ``fid`` (Step 6.7).
* **The body-tag space is closed.**  Top-level ``BODY_TAG_*`` records
  are not self-delimiting without knowing the tag, so a reader MUST
  reject an unknown ``body_tag``.  A new record *kind* is therefore
  not an additive change; it requires a new epoch (a formal-release
  magic bump).  Extend per record via field-IDs, not new tags.

Minimum conformant trace (normative)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A producer that lacks the optional information can still emit a
valid ``.cst``.  The irreducible content a conformant trace MUST
carry:

* **Container:** a tar with one ``header.cst*`` and one ``body.cst*``
  member; the body bracketed by the two ``CST_MAGIC`` markers.
* **Header:** magic; isa; flags; the three window ULEBs;
  ``simpoint_weight`` (``0.0`` when not a simpoint); the four header
  strings (any may be empty); an encoding-maps section carrying at
  least the structurally-required names of Step 3.3 plus an
  (id → name) entry for every numeric value the trace uses; and the
  templates section.
* **Per template:** ``template_id``, ``start_pc``, ``num_insns``,
  ``fall_through_pc`` (0 if the last insn is not a branch),
  ``n_targets`` (0 if not a branch), ``symbol_name`` (may be empty),
  and ``num_insns`` per-insn descriptors.
* **Per insn:** ``pc_delta``, ``opcode``, ``branch_type``, ``flags``,
  ``n_src``, ``n_dst``, ``src_regs[]``, ``dst_regs[]``, ``max_dep_loads``,
  ``max_dep_stores``, ``insn_size``, ``insn_bytes[insn_size]``.
* **Body:** a leading ``BODY_TAG_ASID_SWITCH`` (declaring the opening
  address space, with its inline identity) followed by a
  ``BODY_TAG_THREAD_SWITCH`` (declaring the opening thread); one
  ``BODY_TAG_ENTRY`` per contiguous run of a correct-path BB
  invocation — one entry when the block ran whole, and one per
  uninterrupted stretch when it did not (§4.2a); and for every
  memop an instruction issues, that memop's effective address
  (``CST_FID_LOAD_ADDR{k}`` / ``CST_FID_STORE_ADDR{k}``) together with
  the ``CST_FID_N_LOADS`` / ``CST_FID_N_STORES`` counts; a terminating
  ``BODY_TAG_END`` carrying the ``BODY_TAG_ENTRY`` count.

Everything else is optional and its absence is signalled in-band —
a producer omits it by clearing the gate, and a reader detects the
absence by the same gate:

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Optional content
     - Absent when
   * - Load/store data *values*
     - ``CST_FLAG_MEM_DATA`` clear
   * - Destination-register snapshots
     - ``CST_FLAG_REG_DATA`` clear
   * - Per-memop physical page (``CST_FID_*_PPAGE``, §5.3.1)
     - ``CST_FLAG_PHYSADDR`` clear
   * - Per-template profile block (§6)
     - ``CST_FLAG_PROFILE`` clear
   * - Per-entry fault depth (``CST_FID_BB_FAULT_DEPTH``, §5.7)
     - ``CST_FLAG_FAULT`` clear (system mode only; every entry's depth is then ``0``)
   * - Per-insn dependency sub-block
     - insn's ``CST_INSN_FLAG_HAS_DEP_BLOCK`` clear
   * - Immediate value
     - insn's ``CST_INSN_FLAG_HAS_IMM`` clear
   * - Raw instruction bytes
     - ``insn_size == 0`` (disasm unavailable; opcode/regs still define semantics)
   * - Vector lane masks
     - insn's ``CST_INSN_FLAG_VEC`` clear
   * - Branch-target history
     - ``n_targets == 0``
   * - Symbol name
     - empty ``symbol_name``
   * - Wrong-path chain (per entry)
     - ``CST_FLAG_WP`` clear (the section is omitted from every ENTRY/IFRAME); with the flag set, an individual entry may still carry ``num_wp == 0``
   * - Wrong-path block events (§4.4)
     - the block carries no ``CST_FID_BB_FLAGS`` record and its flag cell reads ``0`` — a block with nothing to report costs no bytes, exactly as any other unchanged field does
   * - Validation IFRAMEs
     - record simply absent (pure redundancy)

Part I: Decoder Recipe
----------------------

Step 0: One-time preparation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A decoder needs three working data structures, all built from the
header member (Step 1):

* ``template_by_id`` — map from ``template_id : u32`` to a parsed
  ``Template`` (start_pc, num_insns, per-insn descriptors).  The
  ``template_id`` is the sole block identity: ``start_pc`` is **not**
  unique.  A self-modified block emits multiple templates that share a
  ``start_pc`` but differ in ``template_id`` and bytes — its revision
  history.  Revisions at one ``start_pc`` are **not required to agree
  in shape**: they may carry different ``num_insns`` and different
  per-instruction PCs and sizes, because the guest may re-cut the block
  into different instructions (kernel alternatives and static-key
  patching, JIT re-emission) and not merely patch bytes in place.
  A block whose EXECUTION was cut short does **not** mint a template:
  its entry names the whole block's ``template_id`` and declares the
  range of it that ran (§4.2a), so the templates section holds one
  entry for the block and the body says how much of it each invocation
  covered.  The one remaining non-self-modifying reason two templates
  share a ``start_pc`` is a block whose TAIL WAS NEVER TRANSLATED — a
  block that spans a page boundary and whose continuation the guest
  never fetched has no whole-block template to name, so what was
  translated is a template in its own right.  Size
  every per-block structure from the ``template_id`` actually
  referenced, never from another revision at the same address.  A
  decoder that also wants a per-pc view builds
  ``templates_by_pc`` (``start_pc → [template_id, …]`` in serialised,
  i.e. body-reference, order); the live revision at any point in the
  body stream is simply whichever ``template_id`` the entries there
  name.  Never resolve a block by ``start_pc`` alone.
* ``encoding_maps`` — twelve maps (``opcode``, ``branch_type``,
  ``reg``, ``field_id``, ``header_flag``, ``insn_flag``, ``body_tag``,
  ``bb_flag``, ``metaflags``, ``dep_block_flag``,
  ``mem_access_pattern``, ``profile_flag``), each
  ``value : u64 → name : string``.  Built from the encoding-maps
  section in Step 1.  (Parsing is generic — Step 3 reads whatever
  maps the section lists — so this enumeration is the set the
  writer emits, not a closed set a decoder must hard-expect.)
* ``ids`` — the numeric IDs the recipe branches on, resolved by
  reverse-lookup of canonical names through ``encoding_maps`` (e.g.
  ``ids.body_tag_entry = encoding_maps.body_tag["BODY_TAG_ENTRY"]``).
  These are the names the byte-level parse depends on; Step 3.3
  enumerates them and states which must always be present and which
  are required only when the construct they tag appears.  Each is
  also named alongside its ``ids.<field>`` use below.

After Step 1 these structures are immutable for the remainder of
the decode.

Step 1: Open the archive and decompress members
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Treat the ``.cst`` file as an opaque POSIX ustar archive (512-byte
header per member, zero-padded to 512-byte boundaries, two trailing
zero blocks at end).

::

   1.1  walk_tar(file):
          loop over 512-byte header blocks until two consecutive zero
          blocks; for each non-zero header, extract member.name and
          member.size; collect into a list keyed by name.
   1.2  body_member  = first member whose name starts with "body.cst"
        header_member = first member whose name starts with "header.cst"
        both members are required; reject otherwise.
   1.3  for each member, look at the filename suffix:
          no suffix      → uncompressed; use the bytes as-is
          ".zst"         → run through `zstd -d -c`
          ".xz"          → run through `xz -d -c`
          ".gz"          → run through `gzip -d -c`
          ".bz2"         → run through `bzip2 -d -c`
          ".lz4"         → run through `lz4 -d -c`
   1.4  the header member is small; decompress it eagerly into RAM
        the body member can be very large; either decompress eagerly
        OR stream the decompressor's stdout into Step 4's body walker.

Step 2: Decode the header member
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After Step 1.4, the (possibly decompressed) header bytes are a flat
byte buffer.  Decode in order; the leading magic doubles as a
sanity check.

::

   2.1  magic        : u32_le   ; must equal 0x1E545343 ("CST" + 0x1E)
   2.2  isa          : u8       ; TraceISA enum (see Reference §2)
   2.3  flags        : u8       ; CST_FLAG_* bitmask (Reference §2)
   2.4  start_insn          : ULEB
   2.5  warmup_insns        : ULEB
   2.6  total_target_insns  : ULEB
   2.7  simpoint_weight     : f64_le  ; raw little-endian IEEE-754
        double (fixed 8 bytes, NOT a varint).  The fraction of
        whole-program execution this segment represents, so a consumer
        can rebuild a whole-program metric as the weighted sum over the
        per-simpoint traces.  0.0 for non-simpoint segments (no
        weighting applies).
   2.8  command      : string
   2.9  datetime     : string
   2.10 comment      : string
   2.11 target_name  : string
   2.12 encoding_maps_section : section    ; see Step 3 for inner shape
   2.13 warmup_end_trace_insn_idx : ULEB
        The TRACE-POSITION index of the warmup→simulation
        boundary: the number of in-trace instructions (the sum of
        each BODY_TAG_ENTRY's template `n_insns`, fan-out records
        included) that precede the first simulation-phase record.
        A consumer walking body records and summing template
        `n_insns` enters the simulation phase the moment that sum
        reaches this value.

        This is NOT an architectural warmup depth.  The segment
        budgets (`warmup_insns`, `total_target_insns`) are
        configured in the window clock's units — the per-TB
        execution count the BBV plugin produces, which is what
        SimPoint offsets are selected from.  The body, by
        contrast, fans REP/MOPS out into one record per
        iteration, so trace position runs AHEAD of the window
        clock whenever a fan-out instruction fires in warmup:
        counting `warmup_insns` body records would leave the
        consumer somewhere in the *middle* of warmup.  This field
        is the bridge: the trace instruction that aligns with the
        bbv-counted architectural warmup boundary.

        Boundary rule (fan-out atomicity): the boundary never
        splits one architectural instruction's records across the
        warmup/measure line.  An architectural instruction whose
        first record precedes the boundary crossing completes
        inside warmup — all its records, and any excursion
        records emitted between its chunks (its own fault or
        interrupt service), count toward this index — while an
        instruction whose first record lands at or after the
        crossing is measured — with one TB-granular refinement:
        fan-out instructions translated into the SAME block as a
        straddling one (an AArch64 SETP/SETM/SETE trio is three
        mid-block fan-out terminators) are held to the same side
        as that block, so a bulk-operation trio never straddles
        the line piecewise.  Warmup records are executed but
        not measured, so a consumer switching phases at this
        index never measures a partially-warmed instruction.
        The rule is generic over fan-out families (x86 REP today;
        AArch64 MOPS when its architectural facts land).

        Sentinel ULEB-encoded `UINT64_MAX` = the warmup boundary
        was not crossed in this segment (the trace was cut short,
        e.g. by guest exit, before warmup elapsed; the whole
        trace is warmup).  0 = warmup ends immediately (no
        warmup configured, e.g. non-simpoint icount mode).
   2.14 templates section := raw payload to end-of-member (no outer
        length-prefix; the templates section runs to the header
        member's EOF).  Decode per Step 4.

Reject the trace if any read attempts to read past the end of the
header member, or if @magic does not match.

Step 3: Parse the encoding maps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``encoding_maps_section`` payload from Step 2.12 is itself
self-describing.  Decode it into a fresh ``encoding_maps`` table.

::

   3.1  n_maps : ULEB
   3.2  repeat n_maps times:
          map_name  : string   ; "opcode" / "branch_type" / ...
          n_entries : ULEB
          repeat n_entries times:
            value : ULEB
            name  : string
          store (value → name) into encoding_maps[map_name].
   3.3  After all maps are read, resolve the names the recipe branches
        on into a fixed-shape `ids` struct by reverse-lookup.  The
        names fall into two groups, by when each must be present:

        (a) Structural, always required.  Every conformant trace
            exercises the constructs these tag, so a trace whose maps
            omit one is rejected here:
              body_tag:    BODY_TAG_END, BODY_TAG_ENTRY,
                           BODY_TAG_THREAD_SWITCH, BODY_TAG_ASID_SWITCH
              header_flag: CST_FLAG_PROFILE, CST_FLAG_WP
              insn_flag:   CST_INSN_FLAG_HAS_IMM,
                           CST_INSN_FLAG_HAS_DEP_BLOCK
              field_id:    CST_FID_BB_START, CST_FID_BB_STOP

            The two range field-IDs are required even though no
            byte-level branch depends on them, because their ABSENCE is
            not detectable from the bytes: a reader that cannot resolve
            them parses every entry correctly and then materialises the
            whole template for a partial entry, over-claiming executed
            instructions with no parse error to show for it (§5.7).
            Rejecting here is what makes that failure impossible.

        (b) Structural, required only when the tagged construct
            appears.  Resolve each if present; its absence is an error
            only if the corresponding record or sub-block occurs:
              body_tag:       BODY_TAG_IFRAME    (iff an IFRAME record
                                                  appears)
              body_tag:       BODY_TAG_REGFILE   (iff a REGFILE record
                                                  appears)
              dep_block_flag: CST_DEP_BLOCK_HAS_REG,
                              CST_DEP_BLOCK_HAS_ADDR
                                                 (iff a dependency
                                                  sub-block appears)
              field_id:       CST_FID_BB_FAULT_INSN
                                                 (iff a block declares
                                                  CST_BB_FLAG_SYNTHETIC_
                                                  FAULT — the index is a
                                                  sibling record, §5.7)
              field_id:       CST_FID_EXTENDED   (iff an extended
                                                  field-delta record
                                                  appears)

        Every other name — all `opcode`, `branch_type`, `reg`,
        `metaflags`, `mem_access_pattern`, and `profile_flag` values,
        the remaining `header_flag` / `insn_flag` / `bb_flag`
        bits, and every `field_id` family/slot name — is resolved
        purely as the recipe encounters its numeric value, under the
        open-map rule: every value that appears has an entry, and a
        value with no entry is malformed.  None of these names is
        required in the abstract — a trace that never uses a construct
        need not name it.

        The tracer, by convention, emits the complete canonical name
        set in every trace — every field-id slot, every flag bit, every
        enum value — so a strict decoder can resolve all IDs up front.
        That is a writer convenience, not a format requirement: neither
        the format nor a conforming decoder depends on any name beyond
        the structural set in (a)–(b) and whatever the trace uses.
        (There are no CST_FID_EXTRA_* fields — all memops are addressed
        through the slotted families; see Reference §5.2.)
   3.4  See Reference §3 for the semantic meaning of each map and ID.

Step 4: Parse the templates section
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The templates payload from Step 2.14 runs to end-of-member.
Decode by repeated outer-section unwrapping.

::

   4.1  num_templates : ULEB
   4.2  repeat num_templates times:
          tmpl_section : section          ; payload is one template
          parse tmpl_section.payload per Step 4.3.
   4.3  Template payload (consumed from tmpl_section):
          template_id        : ULEB
          start_pc           : ULEB
          num_insns          : ULEB
          fall_through_pc    : ULEB       ; not-taken / next-PC edge.
                                          ; Single source of truth — the
                                          ; profile block does NOT repeat
                                          ; it.  0 if last insn isn't a
                                          ; branch.
          n_targets          : ULEB       ; terminal-branch taken-edge
                                          ; targets.  Uniform layout:
                                          ;   0  last insn is not a branch
                                          ;   1  non-indirect branch —
                                          ;      target[0] is the observed
                                          ;      taken edge (0 if the edge
                                          ;      was never resolved)
                                          ;   k  indirect / return —
                                          ;      distinct correct-path-
                                          ;      observed targets, k <=
                                          ;      BRANCH_TARGET_HISTORY (16)
          repeat n_targets times:
            target_pc        : ULEB       ; per-target taken/not-taken
                                          ; counts ride in the profile
                                          ; block, same order & length
          symbol_name        : string     ; may be empty
          repeat num_insns times: one insn descriptor per Step 4.4
          if (header.flags & header_flag.CST_FLAG_PROFILE):
            profile_block                 ; per Step 4.6 (optional)
        After the per-insn descriptors and the optional profile block,
        tmpl_section must be empty; reject otherwise.
   4.4  Per-insn template descriptor (consumed from tmpl_section):
          pc_delta           : ULEB       ; abs PC = prev_pc + pc_delta
                                          ; prev_pc = start_pc for the
                                          ; first insn of the template
          opcode             : u8         ; resolve via encoding_maps.opcode
          branch_type        : u8         ; resolve via encoding_maps.branch_type
          flags              : u8         ; CST_INSN_FLAG_* bitmask
          n_src              : u8
          n_dst              : u8
          src_regs[n_src]    : u8 each    ; resolve via encoding_maps.reg
          dst_regs[n_dst]    : u8 each    ; resolve via encoding_maps.reg
          max_dep_loads      : u8         ; static memory-OPERAND count
                                          ; (not an access count -- see below)
          max_dep_stores     : u8         ; static memory-OPERAND count
          if (flags & ids.insn_flag_has_imm):
            immediate        : SLEB
          insn_size          : u8         ; 0..16
          insn_bytes[insn_size] : raw bytes
          if (flags & ids.insn_flag_has_dep_block):
            decode the optional dependency sub-block per Step 4.5
   4.5  Dependency sub-block (only present when CST_INSN_FLAG_HAS_DEP_BLOCK):
          dep_block_flags    : u8         ; dep_block_flag bits
          if (dep_block_flags & ids.dep_block_has_reg):
            dst_dep[0..n_dst-1]                  : ULEB each
            store_data_dep[0..max_dep_stores-1]  : ULEB each
          if (dep_block_flags & ids.dep_block_has_addr):
            load_addr_dep[0..max_dep_loads-1]    : ULEB each
            store_addr_dep[0..max_dep_stores-1]  : ULEB each
        ``max_dep_loads`` and ``max_dep_stores`` count the instruction's
        static memory OPERANDS, and they exist to size the per-operand
        address-dependency arrays above.  They are not a bound on how
        many accesses an execution performs, and the dynamic count is
        frequently larger: one operand expands into as many accesses as
        the form performs, so AArch64 ``ld4 {v0.16b-v3.16b}, [x1]`` is
        one operand publishing 64 memops, and x86 ``XSAVEOPT`` is one
        operand issuing tens of stores.  One address mask describes every
        access an operand expands into, because they all compute their
        address from the same input registers.  The per-access stream is
        ``CST_FID_N_LOADS`` / ``CST_FID_N_STORES`` and the slot fields
        they gate, bounded by ``CST_FID_SLOT_COUNT``; a consumer sizing a
        per-access array must read those and never these.

        Mask array sizes all come from the outer template header
        (n_dst, max_dep_loads, max_dep_stores) — the dep block itself
        carries only dep_block_flags + the masks.  HAS_REG and HAS_ADDR
        are independent: HAS_REG carries refiner-produced output deps
        (per-dst-reg, per-store-data), HAS_ADDR carries per-memop address
        deps (which src_regs feed the load/store address — so the
        consumer can fire each memop without waiting on inputs
        irrelevant to its address).  See Reference §3 for the bit layout
        inside each mask.

        The two blocks do not have the same SOURCE, and a consumer
        reasoning about how much to trust each should know which.
        HAS_REG is derived from the instruction's decoded operands.
        HAS_ADDR is derived from QEMU's own translation: the address
        provenance its ``tcg_gen_qemu_ld/st`` emitters stated for each
        access, which is what the emulator computed rather than what a
        decoder says the addressing mode names.  The difference is
        visible on x86-64, where a RIP-relative access carries an EMPTY
        address mask — ``gen_lea_modrm_1`` materialises that address
        with ``tcg_gen_movi_tl`` after folding the program counter into
        the displacement at translation time, so no register feeds it
        and there is no producer for a consumer to wait on.

        A constructor that cannot state an instruction's address
        dependency in full omits the HAS_ADDR block entirely rather than
        emitting a mask with a contributor missing from it; the absent
        block is the all-inputs default, and a short mask would let a
        consumer issue an access ahead of a producer it actually
        depends on.
   4.6  Template profile block (consumed from tmpl_section,
        immediately after the last insn descriptor, present only when
        the `CST_FLAG_PROFILE` header bit is set — resolve the
        bit via the `header_flag` map).  This is run-aggregated
        PGO-style metadata; it does not affect replay, and a constructor
        without it omits the block and clears the flag (same optional
        contract as the dep sub-block).  A consumer that does not model
        it may skip the bytes.
          exec_cp            : ULEB   ; #times this BB ran, correct path
          exec_wp            : ULEB   ; #times this BB ran, wrong path
          ;     exec_cp == exec_wp == 0 is VALID: a pre-declared REP
          ;     self-loop sub-template is materialized at translation
          ;     but only emitted when the REP runs >= 2 iterations, so a
          ;     REP never reached / outside the window / run once leaves
          ;     a 0/0 template.  It is never referenced by any body
          ;     entry — treat as an unexercised pre-declared self-loop.
          ; --- terminal-branch per-target taken/not-taken counts,
          ;     consumed 1:1 with the template header's n_targets list
          ;     (same order & length; n_targets is NOT repeated here).
          ;     The not-taken edge is the header's fall_through_pc, which
          ;     this block does NOT repeat.  "Terminal branch" = the BB's
          ;     LAST insn (its first and only branch by the true-BB
          ;     definition; NOT the branch that entered the BB).  Empty
          ;     when the last insn is not a branch. ---
          repeat n_targets times:           ; n_targets from the header
            taken_cp         : ULEB   ; CP execs that took this target
            nottaken_cp      : ULEB   ; CP execs that did NOT (fell
                                      ; through, or — indirect — chose a
                                      ; different target)
            taken_wp         : ULEB
            nottaken_wp      : ULEB
          ;     The header target_pc list is CORRECT-PATH ONLY:
          ;     note_target() is never called during wrong-path
          ;     simulation (the pool feeds the WP target resolver, so a
          ;     speculative entry would be self-defeating).  For a
          ;     non-indirect branch n_targets == 1 and these counts are
          ;     the terminal branch's aggregate CP/WP taken vs fall-
          ;     through.  For an indirect branch the WP taken/not-taken
          ;     aggregate is attributed to target[0] (no per-target WP
          ;     distribution is tracked); CP counts are per target.
          ; --- per-insn, template insn order, num_insns records ---
          repeat num_insns times:
            memops_cp        : ULEB   ; total mem-ops this insn issued, CP
            memops_wp        : ULEB   ; total mem-ops this insn issued, WP
            pat_flags        : u8     ; bit[1:0] cp access-pattern class
                                      ; bit[3:2] wp access-pattern class
                                      ;   Resolve the 2-bit class value
                                      ;   through the `mem_access_pattern`
                                      ;   map (CST_PAT_*) — do NOT assume
                                      ;   fixed numbers.  Classes, by
                                      ;   meaning: no memory access on
                                      ;   that stream; REGULAR (the
                                      ;   abs-magnitude polynomial chain
                                      ;   converges at level 0 — |delta|
                                      ;   constant, covering constant
                                      ;   stride, stride 0, direction
                                      ;   reversals of the same magnitude,
                                      ;   and the 1-sample case);
                                      ;   IRREGULAR (the polynomial chain
                                      ;   converges at some deeper level
                                      ;   k in 1..K-1 — degree-2 through
                                      ;   degree-K polynomial streams —
                                      ;   OR the geometric rescue fires
                                      ;   at some walked level via
                                      ;   |x_n|*|x_{n-2}| = |x_{n-1}|^2 —
                                      ;   pure exponential, or any
                                      ;   polynomial-plus-exponential
                                      ;   mixture up to polynomial degree
                                      ;   K-2); RANDOM (neither test
                                      ;   classifies the step within
                                      ;   CST_PAT_POLY_DEPTH=K=4 levels —
                                      ;   would need degree-(K+1) or
                                      ;   higher polynomial, or a non-
                                      ;   geometric non-polynomial
                                      ;   structure).  The
                                      ;   writer reports the strongest
                                      ;   class observed across the run,
                                      ;   composing a per-insn PC-keyed
                                      ;   classifier with a cross-insn
                                      ;   page-keyed spatial classifier
                                      ;   (lower / more-regular of the
                                      ;   two wins); the exact heuristic
                                      ;   is a writer-side detail, not a
                                      ;   wire contract.
                                      ; bit[4] cp data-is-address
                                      ; bit[5] wp data-is-address
                                      ;   Resolve bits[4]/[5] through the
                                      ;   `profile_flag` map (CST_PROFILE_*);
                                      ;   set when a loaded/stored value
                                      ;   fell in the run's observed addr
                                      ;   window.
            if memops_cp > 0:
              lo_addr_cp     : ULEB   ; lowest effective addr, CP
              hi_addr_cp     : ULEB   ; (highest − lowest), CP
            if memops_wp > 0:
              lo_addr_wp     : ULEB
              hi_addr_wp     : ULEB   ; (highest − lowest), WP

Store every decoded template in ``template_by_id`` keyed by
``template_id``.  After this step the header member is fully parsed
and can be discarded.

Step 5: Open the body member and verify magics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The body member is bracketed by two ``CST_MAGIC`` markers; the
trailing one is the truncation sentinel.  Verify both.

::

   5.1  open the body member's decompressed byte stream.
   5.2  lead : u32_le ; must equal 0x1E545343
   5.3  body record stream := bytes between @lead and the trailing
        CST_MAGIC.  If you have the whole member in memory you can
        peek the last 4 bytes here; for streaming decoders, defer the
        trailing-magic check to Step 7.

Step 6: Walk the body record stream
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The body stream is a flat sequence of tagged records.  Track these
across the walk:

::

   prev_entry_template_id : i32 = 0
   prev_thread_id         : u32 = 0   (the current thread for the next ENTRY)
   prev_asid_index        : u32 = 0   (the current address space, next ENTRY)
   seq_num                : u32 = 0   (BODY_TAG_ENTRY counter)

The context of a body entry is the pair ``(thread_id, asid)``: which
software thread ran the block, and in which address space.  Memory is
keyed ``(asid, vaddr)`` — identical virtual addresses under different
asids are distinct physical memory.  Both dimensions are rebased by
in-body switch records (``BODY_TAG_THREAD_SWITCH``, ``BODY_TAG_ASID_SWITCH``)
and each inherits into every subsequent ``BODY_TAG_ENTRY`` until the next
switch of its dimension.

The body opens with a mandatory initial context declaration: a
``BODY_TAG_ASID_SWITCH`` immediately followed by a ``BODY_TAG_THREAD_SWITCH``,
before the first entry, so the starting ``(asid, thread)`` is stated
explicitly rather than assumed.  Each is an ordinary delta from its base
``0`` (no special-case base): a reader that just applies switch deltas
from 0, like every other delta in the format, arrives at the correct
starting context with no extra knowledge.  A single-address-space
producer declares asid index 0 once and never switches the asid
dimension again; the asid dimension only "activates" once more than one
address space is traced.

``thread_id`` is an **opaque guest-thread identifier**, and the vCPU (host
scheduling slot) the thread ran on is deliberately NOT on the wire — the
consumer maps threads onto simulated cores however its model requires.  In
a system-mode trace the producer derives the id from the guest kernel's
per-thread pointer register, so it names a software thread that is stable
across vCPU migration: a thread that the guest scheduler moves between
vCPUs keeps ONE ``thread_id``, and two threads that time-slice a single vCPU
are two distinct ``thread_id``\ s.  Ids are small integers assigned in
first-sighting order within a segment (0, 1, 2, …); a single-threaded traced
process is ``thread_id`` 0.  In a user-mode trace each guest thread is its
own host thread and ``thread_id`` is that thread's index, likewise stable for
the thread's lifetime — with the one boundary that a user-mode index is
released when its thread exits and may be handed to a thread created later,
so ids are unique among threads that are alive *together* rather than over
all time.  Either way a decoder needs no knowledge of the mapping — it keys
per-thread state (the initial regfile, the field-delta overlays) on the id
as an opaque tag.

Kernel blocks carry the ``thread_id`` of the task that is CURRENT while they
execute, which is not always the thread that entered the kernel: a syscall
or fault handler runs as its caller, but a context switch performed entirely
inside the kernel hands the rest of the strand to the incoming task — a
freshly cloned child finishing its return path before it has ever executed a
user instruction, or a kernel thread scheduled in, is that task and not its
predecessor.  A borrowed-mm kernel thread scheduled onto the gated page
tables is such a strand: it is traced under the gated context's
``asid`` label while carrying its own ``thread_id``, minted from its
own kernel task identity — a thread *within the traced flow*, kept by
ruling.  The producer follows those switches wherever the target's
thread-pointer register still names the current task at kernel privilege
(see :doc:`limitations` for the targets where it does not, and for the
consequences when it does not).  The practical guarantee this buys a
consumer is **strand sequentiality**: filtered to one ``(asid, thread_id)``
context, the entries read as a single instruction stream in order, with
breaks only at the nesting boundaries the format makes visible
(``fault_depth`` changes, privilege-domain gaps).  Two concurrently
executing threads never share a ``thread_id``.

**Address space (asid).**  The ``asid`` values on the wire are *labels*,
never identities: the producer records the live architectural
address-space value at capture through its compact first-sighting index,
and nothing in the format asserts that a label outlives the context it
was read from.  A window (what the producer traces) is identified by its
latched marker virtual address and its content — the anchor ``sig`` word
in the first-sighting identity carries 0.  The ``asid`` dimension names the address space a
block executed in, carried alongside ``thread_id`` as the second half of the
context.  Memory is keyed ``(asid, vaddr)``: the same virtual address under two
asids is two different physical memories, and a consumer that models a cache
or memory hierarchy must qualify every address by the current asid.  The wire
carries a **compact asid index** assigned on first sighting (0, 1, 2, …); each
index's LABEL — the live architectural address-space value at capture
(``root_phys``: CR3 / TTBR0/1 base / SATP PPN / MIPS ``EntryHi.ASID``) plus a
reserved ``sig`` word (always 0) — rides that index's first
``BODY_TAG_ASID_SWITCH``, mirroring how a thread's register file rides its
first ENTRY.  The label is an honest attestation of the value in force, never
an identity a consumer may match across time: the index names a VALUE per
segment, and if the guest reuses the value the index may be reused with it
(minting a fresh index on reuse would require comparing the values as
identities, which the model forbids).

A single-address-space (marker/pin) trace declares asid index 0 in the opening
context record and never switches the asid dimension again: every virtual
address in the body is the pinned process's, and ``thread_id`` distinguishes the
software threads *within* it.  Within that one address space a ``thread_id``'s
USER-code blocks are exact wherever the guest scheduler runs the thread (the
per-thread pointer is a user register that survives migration); a migrating
pinned process is, however, outside the clean-attribution envelope for its
KERNEL code, which carries no per-thread register.  The producer keeps the
process inside the envelope by pinning it to one core (``cst_attach`` does this
by default) and emits a diagnostic if it observes the process spanning vCPUs.
Whole-system multi-address-space capture — several processes' asids
interleaved in one body, with the kernel's shared upper half resolving to the
same physical memory across all asids — builds on this same record and is
staged in.  See ``docs/architecture.rst``, "Single address space".

Loop until a ``BODY_TAG_END`` is seen:

::

   6.1  tag : u8
        dispatch on tag against the ids resolved in Step 3:
          ids.body_tag_thread_switch  → Step 6.2
          ids.body_tag_asid_switch    → Step 6.2a
          ids.body_tag_regfile        → Step 6.3
          ids.body_tag_devio_start    → Step 6.3a  (system-mode disk I/O)
          ids.body_tag_devio_stop     → Step 6.3a
          ids.body_tag_entry          → Step 6.4
          ids.body_tag_iframe         → Step 6.5
          ids.body_tag_end            → Step 6.6 (terminates loop)
          any other value             → malformed; reject
          (ids.body_tag_devio_* are absent from device-free traces; a
           decoder that never resolves them simply never dispatches here.)
   6.2  THREAD_SWITCH record:
          thread_id_delta : SLEB
          prev_thread_id += thread_id_delta
          (No state output; the next ENTRY inherits prev_thread_id.)
   6.2a ASID_SWITCH record:
          asid_index_delta : SLEB
          prev_asid_index += asid_index_delta
          if (this asid_index is seen for the FIRST time in the body):
            root_phys : u64        ; page-table root physical address
            sig       : u64        ; content signature (0 when unassigned)
          The identity (`root_phys`, `sig`) rides an index's first sighting
          only — exactly as a thread's register file rides its first ENTRY
          (Step 6.3).  A repeat sighting carries the bare index delta with
          no trailing identity.  A decoder tracks which asid indices it has
          already seen to know whether to read the two identity words.
          (No state output; the next ENTRY inherits prev_asid_index.)
   6.3  REGFILE record:
          thread_id : ULEB
          n_present : ULEB
          repeat n_present times:
            gen_id : u8
            width  : u8
            bytes[width] : raw
          Emit a per-thread initial-regfile snapshot for `thread_id`.
          Each `bytes[width]` payload is little-endian (the producer
          normalises from target byte order before write), so decoders
          interpret it as a little-endian unsigned scalar of `width`
          bytes regardless of guest endianness.
   6.3a DEVIO_START / DEVIO_STOP record (system-mode disk I/O, §4.1b):
          DEVIO_START:
            request_id : ULEB
            rw         : u8            ; 0=read 1=write 2=flush
            bytes      : ULEB          ; 0 for flush
            block      : ULEB          ; byte offset / 512
            attr       : u8            ; 0=positional 1=exact
            if attr == 1 (exact):
              owner_thread_id : ULEB   ; the issuing process/thread
              owner_asid      : ULEB   ; its context asid_index
          DEVIO_STOP:
            request_id : ULEB
          Owner attribution.  When attr == 1 (exact) the request was
          correlated to the vCPU that rang the device doorbell, so the
          owning (thread_id, asid) is carried inline — use it directly,
          independent of where the record fell in the interleaved stream.
          When attr == 0 (positional) no owner is carried: surface the
          record under the current (prev_asid_index, prev_thread_id)
          context, as before.  A STOP correlates to its START by
          request_id and inherits that START's owner.  No state output;
          the next ENTRY is unaffected.
   6.4  ENTRY record:
          template_id_delta : SLEB
          cur_template_id = prev_entry_template_id + template_id_delta
          prev_entry_template_id = cur_template_id
          cp_delta_section   : section          ; see Step 6.7
          if (header.flags & header_flag.CST_FLAG_WP):
            wp_chain_section  : section          ; see Step 6.8
          ; when CST_FLAG_WP is clear the wp_chain_section is absent
          ; and the entry has no wrong-path chain (num_wp treated as
          ; 0).
          ;
          ; The entry has no other payload.  Everything that is a fact
          ; about the BLOCK rather than about one of its instructions —
          ; the executed range, the fault depth, the block flags —
          ; rides cp_delta_section as an ordinary field-delta record at
          ; the reserved block position (Step 6.7, §5.7), so an entry
          ; with nothing block-level to report carries no bytes for it.
          seq_num += 1
          Read the block's range from the field state after decoding
          cp_delta_section:
            bb_start = cell(cur_template_id, BLOCK_POS, CST_FID_BB_START)
            bb_stop  = cell(cur_template_id, BLOCK_POS, CST_FID_BB_STOP)
          where BLOCK_POS = template.num_insns and the cells' baseline
          defaults are 0 and template.num_insns respectively (§5.7).
          Reject the entry if not 0 <= bb_start < bb_stop <= num_insns.
          Emit a CP body entry tagged (seq_num, cur_template_id,
          prev_thread_id, prev_asid_index) carrying the cp_delta_section's
          decoded dyn_params + reg_snaps for instructions
          [bb_start, bb_stop) ONLY, the block-level cells, and the
          wp_chain_section's WPEntries.
   6.5  IFRAME record (validation-only; producers may omit it):
          cp_delta_section   : section
          if (header.flags & header_flag.CST_FLAG_WP):
            wp_chain_section  : section          ; see Step 6.8
          Decode each section against fresh "nothing observed yet"
          overlays; the values reconstructed must match the
          immediately-preceding ENTRY exactly (template_id, dyn_params,
          reg_snaps, the block-level cells including bb_start/bb_stop,
          WP chain).  IFRAMEs do not advance prev_entry_template_id and
          do not emit a body entry.
   6.6  END record:
          num_entries : ULEB
          must equal the total number of BODY_TAG_ENTRY records seen
          since the start of the body stream.  Exit the loop.
   6.7  CP field-delta section payload:
        ; The `: section` field in Step 6.4 already read this section's
        ; len:ULEB; the steps below decode payload[len].  `len` (bytes)
        ; and `n_records` (count) are independent — an empty section is
        ; len=1 / n_records=0 (the single byte IS the n_records=0 ULEB).
          N = num_insns of the template THIS section describes:
              the ENTRY's cur_template_id (Step 6.4), the chain
              block's wp template (Step 6.8), or the preceding
              ENTRY's template for an IFRAME (Step 6.5).  Never any
              other template's num_insns — revisions at one start_pc
              need not agree in shape (Step 0), so N is a per-section
              quantity, resolved from the referenced template_id.
          n_records : ULEB
          ipos : u32 = 0                  ; reset at section start; not
                                          ; carried across sections
          repeat n_records times: one field-delta record per Step 6.9;
            after the record's ipos_delta is applied, branch on ipos:
              ipos <  N   → the record addresses instruction ipos of
                            the referenced template
              ipos == N   → the record addresses the BLOCK itself (the
                            reserved position, BLOCK_POS)
              ipos >  N   → malformed; reject the trace.  Do NOT skip
                            the record and continue: no position above
                            BLOCK_POS exists in this epoch, and a
                            cursor past it means the decode has
                            desynchronised or the writer is defective.
        After all records are consumed the section payload must be
        empty.
        ; The dispatch above is closed — every record addresses either
        ; one instruction or the block, decided by ipos alone.  A
        ; decoder looping "per instruction" must route ipos == N to
        ; the block, never treat it as an out-of-range instruction
        ; index.  Records arrive in non-descending (ipos, fid) order
        ; (§5), and BLOCK_POS is the section's highest position, so
        ; the block's records are always the section's last: apply the
        ; WHOLE section before interpreting the entry (§5.7) — the
        ; executed range a block record declares arrives after the
        ; per-instruction records it scopes.
   6.8  WP chain section payload:
          num_wp : ULEB
          repeat num_wp times:
            wp_template_id_delta : SLEB
            wp_delta_section     : section    ; decode per Step 6.7
        ; Each wp_delta_section carries that speculative block's own
        ; block-level records at its own BLOCK_POS — its range, and any
        ; CST_FID_BB_FLAGS / CST_FID_BB_FAULT_INSN it needs (§4.4).
        ; num_wp is the bare block count: nothing is packed into it.
   6.9  One field-delta record:
          ipos_delta : ULEB    ; running ipos += ipos_delta (sparse positions)
          fid        : ULEB    ; resolve via encoding_maps.field_id
                                 (writer packs hot fields into the
                                  1-byte ULEB range; cold and high-slot
                                  fields spill to 2)
          delta      : SLEB_WIDE   (up to 512 bits, signed; same shape
                                    as ULEB_WIDE but the high bit of the
                                    last byte's payload extends the sign)
          if fid == ids.fid_extended:
            ext_payload : ULEB    (reserved escape; reserve only)
          Update the per-template field-state cell at (template_id,
          ipos, fid) by adding the decoded delta modulo 2^512.  See
          Reference §5 for the field-state semantics.
          Then check the resolved field name against the record's
          position (Step 6.7's dispatch):
            a block-level name (the CST_FID_BB_* family, §5.7) at an
            instruction position (ipos < N), or a per-instruction
            name at BLOCK_POS (ipos == N), is malformed — reject.
            A name the decoder does not implement is exempt: the
            record was already consumed whole (the LEB framing fixes
            its length), so skip it and continue at either position —
            that is the additive-evolution path (Forward
            compatibility, above).  The reject applies to names the
            decoder KNOWS, found where they cannot occur.

All memops are addressed through the slotted families
(``LOAD_ADDR[0..511]`` / ``STORE_ADDR[0..511]`` and their ``DATA``
counterparts); there is no overflow vector.  An instruction whose
dynamic memop count exceeds ``CST_FID_SLOT_COUNT`` (512) has the
excess dropped at the writer.

A SLEB_WIDE / ULEB_WIDE primitive: like LEB128 but the value is
read into up to 8 little-endian limbs (64 bits each, packing
7 bits per byte across limbs).  For SLEB_WIDE, if the final byte's
0x40 bit is set, sign-extend the remaining high bits to 1.

Step 7: Verify the trailing magic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After Step 6 finishes (BODY_TAG_END was consumed), read 4 more
bytes from the body member's stream:

::

   7.1  trail : u32_le   ; must equal 0x1E545343
   7.2  the body member's stream must be exhausted at this point
        (no further bytes).  Reject otherwise.

If you streamed the body through a subprocess decompressor (Step
1.4 streaming path), this is also the right moment to call wait()
on the child and require a zero exit status.

Part II: Reference
------------------

1. File Layout
~~~~~~~~~~~~~~

A ``.cst`` file is a POSIX **ustar** archive carrying exactly two
regular-file members.  Each member is independently byte-aligned and
optionally compressed; the compression algorithm is encoded in the
member's filename suffix.

::

   .cst (POSIX ustar archive)
   +-----------------------------------------+
   | body.cst[.<codec>]                      |  member 1 (body first)
   |   CST_MAGIC                u32          |
   |   body record stream                    |
   |   BODY_TAG_END  num_entries:ULEB        |
   |   CST_MAGIC                u32          |  trailing magic; truncation marker
   +-----------------------------------------+
   | header.cst[.<codec>]                    |  member 2
   |   CST_MAGIC                u32          |
   |   isa / flags / window descriptors      |
   |   strings (command, datetime, ...)      |
   |   encoding maps section                 |
   |   templates section                     |
   +-----------------------------------------+

``<codec>`` is one of ``.zst``, ``.xz``, ``.gz``, ``.bz2``, ``.lz4``, or omitted
entirely (uncompressed).  When the tracer is run with ``compress=<cmd>``
the writer streams each member's bytes through that command and renames
the in-archive member to match the resulting payload (e.g.
``body.cst.zst``).  The body is always written first so that header
finalisation can include the final template count.

Decoders should treat the archive as opaque, find both members by
prefix match (``body.cst*`` and ``header.cst*``), dispatch a decompressor
based on the trailing suffix, and parse each member as described
below.  There is no global file trailer and no global offset table:
each member is fully self-describing once you have its raw bytes.

The body refers to template IDs, and templates describe the static
instruction shape for each basic block. Dynamic fields in the body are
sparse deltas from the template default or from the most recent emitted
state for the same field.

2. Constants
~~~~~~~~~~~~

::

   CST_MAGIC              = 0x1E545343       bytes: 'C' 'S' 'T' 0x1E
   CST_FID_SLOT_COUNT     = 512              max memops / dst regs per insn

``CST_MAGIC`` and ``CST_FID_SLOT_COUNT`` are the only numerically-fixed
constants in the format: a reader compares the magic literally, and
``CST_FID_SLOT_COUNT`` is the per-family slot ceiling.  Every other
numeric ID — body tags, opcodes, branch types, register IDs, field
IDs, flag-bit positions — is resolved through the per-trace encoding
maps (§3.1) and is not pinned by this specification.  The body-tag
values the writer currently assigns are ``BODY_TAG_END = 0``,
``BODY_TAG_ENTRY = 1``, ``BODY_TAG_THREAD_SWITCH = 2``,
``BODY_TAG_IFRAME = 3``, ``BODY_TAG_REGFILE = 4``,
``BODY_TAG_ASID_SWITCH = 5``, and — only in system-mode traces with the
disk-I/O hook active (§4.1b) — ``BODY_TAG_DEVIO_START = 6`` and
``BODY_TAG_DEVIO_STOP = 7``; a decoder obtains them from the ``body_tag``
map, not from these numbers.  The two DEVIO names are present in the map
only when a trace can carry disk records, so a device-free trace keeps
the historical six-entry ``body_tag`` vocabulary.

The body member begins with ``CST_MAGIC`` and ends with ``CST_MAGIC``.  A
file is treated as truncated if the trailing magic is missing.  The
header member begins with ``CST_MAGIC`` (no trailing magic; the member
naturally ends after its templates section).

``CST_FID_SLOT_COUNT`` is the per-family slot ceiling for the
field-delta sections (loads, stores, destination registers).  Should
an instruction's dynamic memop count exceed this cap, the writer
clamps the trailing memops and emits a warning to
``unknown_warnings.log``; there is no ``EXTRA_*`` overflow path.  The
clamp is a backstop only — the instructions that could reach it are
fanned out into a self-loop of one entry per iteration instead (see
Reference §5.2).

Field-delta ``fid`` is a ULEB128.  Numeric field-IDs are
non-normative — readers consume the header's ``field_id`` encoding
map.  The writer typically packs the hot fields into the 1-byte
ULEB range, but the layout is its concern, not the format's (see
Reference §5.1).

On ISAs with an integer flags register (x86, AArch64), every insn
whose template writes that register also emits a canonical
ISA-agnostic Z/N/C/V/P byte under ``CST_FID_METAFLAGS`` in the per-insn
field-delta stream.  The byte is gated on ``CST_FLAG_REG_DATA`` and is
otherwise absent; on ISAs with no integer flags reg (RISC-V, MIPS)
the FID never appears.

The metaflags byte carries an ISA-agnostic condition-flags summary,
computed by the plugin via a per-ISA shuffle of the guest's native
flags register (not directly readable from QEMU).  Each flag is
resolved through the ``metaflags`` encoding map — the trace assigns the
bit, a reader never assumes a position:

- ``CST_METAFLAGS_Z`` — zero / equal
- ``CST_METAFLAGS_N`` — negative / sign
- ``CST_METAFLAGS_C`` — unsigned carry / borrow
- ``CST_METAFLAGS_V`` — signed overflow
- ``CST_METAFLAGS_P`` — parity (x86 only)

The guest-to-canonical correspondence is by flag, not by position: x86
``EFLAGS`` CF→C, PF→P, ZF→Z, SF→N, OF→V; AArch64 ``NZCV`` (top nibble of
CPSR) N→N, Z→Z, C→C, V→V (no parity).

Readers reject any file whose magic disagrees with ``CST_MAGIC``.

The MEM_DATA / REG_DATA / PHYSADDR / FAULT bits are advisory hints about
field families — the field IDs still determine what actually appears in
each delta section.  CST_FLAG_PROFILE and CST_FLAG_WP are structural:
they gate the presence of whole blocks (the
per-template profile block — Step 4.6 / §6, and the per-entry
wrong-path chain section — Steps 6.4–6.5), exactly as the
per-insn CST_INSN_FLAG_HAS_DEP_BLOCK gates the dep sub-block.  Resolve
every flag through the ``header_flag`` map — the trace assigns each bit,
a reader never assumes a position:

- ``CST_FLAG_MEM_DATA`` — LOAD_DATA / STORE_DATA may appear
- ``CST_FLAG_REG_DATA`` — DST_REG fields may appear
- ``CST_FLAG_PROFILE`` — per-template §6 profile block present
- ``CST_FLAG_WP`` — per-entry wrong-path chain present (§4.3)
- ``CST_FLAG_FAULT`` — ``CST_FID_BB_FAULT_DEPTH`` may appear (§5.7);
  system mode only — a user-mode trace never sets it and every entry's
  depth is ``0``.  Advisory: the field-ID is what actually carries the
  depth, so a reader that simply reads the cell is correct either way
- ``CST_FLAG_PHYSADDR`` — ``CST_FID_*_PPAGE`` families may appear
  (§5.3.1); system mode only (``physaddr=1``); its name is present in
  the ``header_flag`` map only when physical-page capture is active, so
  a non-``physaddr`` trace keeps the historical five-entry
  ``header_flag`` vocabulary (MEM_DATA, REG_DATA, PROFILE, WP, FAULT)

Per-instruction template flags, resolved through the ``insn_flag`` map
(again: names, not fixed positions):

- ``CST_INSN_FLAG_BRANCH_COND`` — conditional branch
- ``CST_INSN_FLAG_HAS_IMM`` — carries an immediate
- ``CST_INSN_FLAG_ATOMIC`` — atomic / locked memory op
- ``CST_INSN_FLAG_VEC`` — per-operand lane masks emitted
- ``CST_INSN_FLAG_LANE_PARALLEL`` — lane k of each dst depends only on
  lane k of every src
- ``CST_INSN_FLAG_HAS_DEP_BLOCK`` — intra-instruction dep mask present
- ``CST_INSN_FLAG_SYSTEM`` — privileged (non-user) execution context;
  uniform across a template, always clear in user-mode traces

(Bit 3 is reserved — it formerly carried ``CST_INSN_FLAG_STATIC``, retired
with the executable-region sweep.  Never-executed coverage is now supplied
by opportunistic branch-alternate minting, whose templates carry no flag.)

``CST_INSN_FLAG_SYSTEM`` distinguishes the kernel instructions of a
system-mode trace (the traced-but-not-counted privileged execution of
the pinned process, per the marker count set) from its user
instructions.  It is uniform across a template — a true basic block
never straddles a privilege transition, since the transition
instruction (syscall / interrupt entry / return) seals the block.
User-mode traces, and traces predating the flag, omit the name from the
``insn_flag`` map and never set the bit; a consumer resolves an absent
name as "always user".

Never-executed fetch/decode coverage (``static_templates=1``) is delivered
by opportunistic branch-alternate minting.  A minted alternate is an
**ordinary** dictionary entry carrying **no** distinguishing wire flag: it
is a template whose profile counts are zero and which no body record
references, indistinguishable from any block that simply never executed —
because that is exactly what it is.  A consumer reconstructing a wrong path
from the binary resolves fall-through and branch-target PCs against the
dictionary as a whole; it does not need to tell minted from merely-unexecuted
blocks apart.  A block that is both minted and later executed is carried by
its executed template (real id, real profile), which shadows the alternate at
serialization.  The trace is byte-identical in the body whether or not the
feature is on; the delta is templates-section-only.

``dep_block_flag`` map (only inspected when ``CST_INSN_FLAG_HAS_DEP_BLOCK``
is set on the per-insn flag byte), resolved through the
``dep_block_flag`` map:

- ``CST_DEP_BLOCK_HAS_REG`` — dst_dep + store_data_dep present
- ``CST_DEP_BLOCK_HAS_ADDR`` — load_addr_dep + store_addr_dep present

Block-level flags, resolved through the ``bb_flag`` map.  They are the
bits of the ``CST_FID_BB_FLAGS`` block-level field (§5.7), which every
correct-path and wrong-path block can carry:

- ``CST_BB_FLAG_SYNTHETIC_FAULT`` — this wrong-path block consumed
  synthetic data; the instruction index rides the sibling
  ``CST_FID_BB_FAULT_INSN`` (§4.4)
- ``CST_BB_FLAG_TRANSLATION_UNAVAIL`` — this wrong-path block is its
  excursion's last: the next speculative fetch could not be translated
  (§4.4)
- ``CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL`` — set on a *correct-path*
  entry whose wrong-path excursion was kicked but whose first target
  could not be fetched, so the chain is empty (§4.4)
- ``CST_BB_FLAG_THREAD_END`` — this entry is the last one this
  ``(thread_id, asid)`` context contributes to the segment (§4.2a)
- ``CST_BB_FLAG_BRANCH_UNRESOLVED`` — this entry's range contains its
  terminating branch, but the successor was never observed; the
  branch-outcome cells were not re-staged and hold a stale repeat, not
  this block's outcome (§5.6)

The vocabulary is open like every other map: a bit whose name the
trace does not carry is not set anywhere in that trace, and a reader
that meets an unrecognised bit ignores it, per the reserved-bits rule.

3. Header
~~~~~~~~~

The header member is byte-aligned by construction.  It is written last
(so the writer can include the final template count) but is logically
the first thing a decoder needs.

::

   +--------------------------------------------------+
   | magic               u32  = 0x1E545343            |
   | isa                 u8   TraceISA                |
   | flags               u8   CST_FLAG_* bits         |
   | start_insn          ULEB                         |
   | warmup_insns        ULEB                         |
   | total_target_insns  ULEB                         |
   | simpoint_weight     f64   little-endian binary64  |
   +--------------------------------------------------+
   | command             string                       |
   | datetime            string                       |
   | comment             string                       |
   | target_name         string                       |
   +--------------------------------------------------+
   | encoding_maps_section                            |
   |   section := len:ULEB payload[len]               |
   +--------------------------------------------------+
   | templates_section                                |
   +--------------------------------------------------+  member EOF

``start_insn`` is the architectural instruction count at which this
segment begins, anchoring the body records to a global instruction
timeline.  ``warmup_insns`` is the number of instructions at the front
of the trace meant to prime caches and branch predictors and not be
evaluated; it is zero outside simpoint mode and on simpoint runs with
no warmup configured.  ``total_target_insns`` is the configured length
of the segment — ``warmup_insns + simulation_insns`` for simpoint
segments, or ``stop - start`` for non-simpoint runs with an explicit
stop.  A value of zero means "unbounded" (non-simpoint runs with no
explicit stop trace until the program exits, so the targeted total is
not known at header-write time).  These three values describe the
*targeted* window.  A user-mode segment with an explicit stop bills at
emit and cuts its final entry's range so the emitted user instruction
count equals the target exactly (the one carve-out is a self-loop
fan-out instruction, whose iterations are indivisible on the wire —
§4.2a); a system-mode budget close may overshoot by the remainder of
the block that carried the clock across the stop.  ``simpoint_weight``
is the fraction of whole-program execution this segment represents
(``0.0`` for a non-simpoint segment); a consumer rebuilds a
whole-program metric as the weighted sum over the per-simpoint
traces.

Because the header lives in its own archive member, a decoder knows
the header end exactly: it is the member's payload size.  The
templates section runs from the byte immediately after the encoding
maps section through end-of-member.

3.1 Encoding Maps
^^^^^^^^^^^^^^^^^

The encoding map section makes the trace self-describing. Numeric IDs in
templates and dynamic fields can be resolved by reading the header rather
than assuming a fixed convention such as ``241 == REG_ZERO``.

::

   encoding_maps_section payload:

     n_maps : ULEB

     repeat n_maps times:
       map_name  : string       example: "reg"
       n_entries : ULEB

       repeat n_entries times:
         value   : ULEB         numeric value stored elsewhere in the trace
         name    : string       example: "REG_ZERO"

Per-thread initial register files are emitted as ``BODY_TAG_REGFILE``
records inline in the body stream (see §4.6), not as part of the
``reg`` encoding map.

A slotted family contributes one ``(value, name)`` pair per slot, so the
``field_id`` map is the one section whose size tracks
``CST_FID_SLOT_COUNT``: about 180 KiB per segment header at 512 slots.
It is highly repetitive text and compresses to a few KiB under the
container codec. Two consequences for readers:

* The map states what *this trace* can address. A writer built against a
  narrower slot ceiling names only the slots it can emit, so a reader
  must bound per-slot materialisation by the names actually present, not
  by its own compile-time ceiling — otherwise a trace whose dynamic
  memop count was clamped at the writer's ceiling (``n_stores`` records
  the pre-clamp count; see §5.2) yields phantom zero memops for the
  clamped tail.
* A slot's absence is not an error and is not the same as the slot being
  present with a zero value.

The writer emits these maps:

::

   +---------------+-----------------------------------------------+
   | map_name      | Values described                              |
   +---------------+-----------------------------------------------+
   | opcode        | GenericOpcode values, GEN_OP_*                |
   | branch_type   | BranchType values, BRANCH_*                   |
   | reg           | GenericRegId values, REG_*                    |
   | field_id      | CST_FID_* sparse delta field IDs              |
   | header_flag   | CST_FLAG_* header bits                        |
   | insn_flag     | CST_INSN_FLAG_* template flag bits            |
   | dep_block_flag| CST_DEP_BLOCK_* dep sub-block flag bits       |
   | body_tag      | BODY_TAG_* stream record tags                 |
   | bb_flag       | CST_BB_FLAG_* block-level flag bits           |
   | metaflags     | CST_METAFLAGS_* canonical flag bits           |
   | mem_access_pattern | CST_PAT_* template-profile access classes|
   | profile_flag  | CST_PROFILE_* template-profile pat_flags bits |
   +---------------+-----------------------------------------------+

The template profile block (§6) is self-describing through these
last two maps: resolve ``pat_flags`` bits[1:0]/[3:2] via
``mem_access_pattern`` and bits[4]/[5] via ``profile_flag`` rather than
hard-coding the class meanings.

Consumers resolve numeric IDs through the maps in the trace.  The
writer populates each map with its full canonical name set; Step 3.3
states which names a conformant trace is actually required to carry.

4. Body Stream
~~~~~~~~~~~~~~

Conceptually, every ``BODY_TAG_ENTRY`` record describes one
*uninterrupted run of instructions* within one invocation of one true
basic block on the architectural correct path.  Each record carries:
the template ID (which gives the static instruction sequence), the
half-open range ``[bb_start, bb_stop)`` of that template the run
covered (§4.2a — ``[0, num_insns)``, the whole block, unless the record
says otherwise), every load and store address that fired for an
instruction inside that range (and value, if ``MEM_DATA`` is on), the
post-execution snapshot of every destination register those
instructions wrote (if ``REG_DATA`` is on), and the wrong-path chain — a
sequence of speculative basic-block invocations the CPU would have run
if its branch predictor had resolved the just-completed branch the
other way.  An invocation the guest ran straight through is one
record; an invocation something interrupted is one record per stretch
it ran, in the order it ran them.  The field-delta encoding scheme
below is a compression layer over that conceptual picture, not a
different shape of data.

**Order.**  Within one ``(thread_id, asid)`` context the records appear
in strict program order, unconditionally: a block is emitted when
execution leaves it, at the extent that ran, so nothing is ever held
back to be placed later.  Across contexts the stream interleaves in
dispatch order.  A consumer filtering to one context therefore reads a
single instruction stream with no reordering to undo and no rule to
special-case — see §4.2a.

The body stream is a sequence of tagged records ending in one footer.
It opens with a mandatory context declaration — a ``BODY_TAG_ASID_SWITCH``
(§4.1a) followed by a ``BODY_TAG_THREAD_SWITCH`` (§4.1) — so the starting
``(asid, thread)`` context is stated explicitly before any entry.

::

   body stream:

     +------------------------------+
     | tag = BODY_TAG_ASID_SWITCH   |   always the first record;
     | asid switch payload          |    declares the opening asid
     +------------------------------+
     | tag = BODY_TAG_THREAD_SWITCH |   always the second record;
     | thread switch payload        |    declares the opening thread
     +------------------------------+
     | tag = BODY_TAG_REGFILE       |   (optional, per-thread initial
     | regfile payload              |    register state — §4.6)
     +------------------------------+
     | tag = BODY_TAG_ENTRY         |
     | entry payload                |
     +------------------------------+
     | tag = BODY_TAG_IFRAME        |   (optional, validates the
     | iframe payload               |    preceding ENTRY)
     +------------------------------+
     | tag = BODY_TAG_END           |
     | num_entries : ULEB           |
     +------------------------------+

``num_entries`` must match the number of ``BODY_TAG_ENTRY`` records seen.
``BODY_TAG_IFRAME`` records are not counted; they are pure
validation/resync redundancy.

It is a count of RECORDS, not of block invocations: an invocation that
ran in several stretches contributes one record per stretch (§4.2a).  A
consumer sizing a per-invocation structure from ``num_entries``
over-counts by exactly the number of interruptions the segment
contains; the quantity that counts invocations is the number of
records whose ``bb_start`` is ``0``.

4.1 BODY_TAG_THREAD_SWITCH
^^^^^^^^^^^^^^^^^^^^^^^^^^

Thread switches are sparse records in the body stream. Normal basic
block entries inherit the current thread ID until the next switch record,
so traces do not pay a per-block thread field.

::

   +--------------------------------------------------+
   | tag = 2                         u8               |
   | thread_id_delta                 SLEB             |
   |   current_thread_id - previous_thread_id         |
   +--------------------------------------------------+

``previous_thread_id`` starts at 0. A decoder updates the current thread
state when it sees this tag and associates that thread ID with following
``BODY_TAG_ENTRY`` records.

4.1a BODY_TAG_ASID_SWITCH
^^^^^^^^^^^^^^^^^^^^^^^^^

Address-space switches are sparse records, sibling to the thread switch.
Normal basic-block entries inherit the current asid index until the next
switch record, so traces do not pay a per-block asid field.  Memory is
keyed ``(asid, vaddr)``: a consumer qualifies every address by the current
asid, and identical VAs under different asids are distinct physical
memory.

::

   +--------------------------------------------------+
   | tag = 5                         u8               |
   | asid_index_delta                SLEB             |
   |   current_asid_index - previous_asid_index       |
   | -- present only on this index's FIRST sighting --|
   | root_phys                       u64  (LE)        |
   |   address-space value at first sighting (label)  |
   | sig                             u64  (LE)        |
   |   reserved; always 0                             |
   +--------------------------------------------------+

``previous_asid_index`` starts at 0.  The **compact asid index** is
assigned on first sighting (0, 1, 2, …).  ``root_phys`` is a **label**
— an honest attestation of the live architectural address-space value
in force at first sighting (CR3, TTBR0/1 base, SATP, or the MIPS
``EntryHi.ASID`` field), never an identity a consumer may match across
time.  The index labels a VALUE per segment, not a process, and may be
reused if the guest reuses the value (minting a fresh index on reuse
would require detecting reuse, i.e. comparing roots as identities,
which the model forbids).  ``sig`` is reserved and always 0.  Both
words ride that index's first switch record only.  A decoder tracks which indices it has already seen;
a repeat sighting of an index carries the bare ``asid_index_delta`` with no
trailing identity words.  This first-sighting-inline scheme mirrors the
per-thread register file (§4.6) and keeps the stream self-describing
without a header-side asid table.

Every trace opens with an initial ``BODY_TAG_ASID_SWITCH`` (before the
opening ``BODY_TAG_THREAD_SWITCH``), declaring the address space the trace
starts in.  A single-address-space trace declares index 0 once and never
switches the asid dimension again.

4.1b BODY_TAG_DEVIO_START / BODY_TAG_DEVIO_STOP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Block-device (disk) I/O requests are bracketed in the body stream by a
pair of sparse records.  They appear only in **system-mode** traces that
generate disk traffic; a device-free trace (every user-mode trace)
carries none, and their names are omitted from the ``body_tag`` encoding
map, so such traces are byte-identical to the pre-DEVIO format.  The two
tag names appear in the map only when the disk-I/O hook is active (the
``devio`` option on, system mode).

::

   BODY_TAG_DEVIO_START
   +--------------------------------------------------+
   | tag = 6                         u8               |
   | request_id                      ULEB             |
   |   compact monotonic id, per segment (from 1)     |
   | rw                              u8                |
   |   0 = read, 1 = write, 2 = flush (CST_DEVIO_*)   |
   | bytes                           ULEB             |
   |   request length in bytes (0 for flush)          |
   | block                           ULEB             |
   |   disk block number = byte offset / 512          |
   | attr                            u8                |
   |   0 = positional, 1 = exact  (CST_DEVIO_ATTR_*)  |
   |                                                  |
   | -- present iff attr == 1 (exact) --              |
   | owner_thread_id                 ULEB             |
   |   the issuing process/thread                     |
   | owner_asid                      ULEB             |
   |   its context asid_index                         |
   +--------------------------------------------------+

   BODY_TAG_DEVIO_STOP
   +--------------------------------------------------+
   | tag = 7                         u8               |
   | request_id                      ULEB             |
   |   the id of the START this completion pairs with |
   +--------------------------------------------------+

**Owner attribution.**  A block request is issued from the block backend,
which — under the canonical no-iothread configuration — may run off the
issuing vCPU thread, so the record's position in the interleaved stream
does not by itself identify the owner.  When the request was correlated
to the vCPU that rang the device doorbell (see below), ``attr = 1`` (exact)
and the owning ``(owner_thread_id, owner_asid)`` is carried **inline**; a
consumer uses it directly and needs no positional guess.  This is what
makes attribution correct for a multi-vCPU / multi-process trace where
two processes' disk I/O interleaves in one body stream.  When no doorbell
matched — a non-virtio device (IDE/AHCI), or kernel-internal I/O — `attr =
0` (positional) and no owner is carried: the consumer attributes the
record to the ``(asid, thread)`` context in force at its stream position, as
a device-free trace never emits these records at all.  A ``DEVIO_STOP``
correlates to its ``DEVIO_START`` by ``request_id`` and inherits that START's
owner; a ``DEVIO_STOP`` never precedes its ``DEVIO_START`` on the wire.

**Exact attribution requires a virtio-blk device kicked in vCPU context.**
The guest's virtqueue kick (``virtio_queue_notify``) executes on the issuing
vCPU; the plugin captures that vCPU's owning ``(thread, asid)`` there and
queues it, with the device token, on a small bounded FIFO owned by that
vCPU.  The block backend's later issue is matched against that SAME
vCPU's FIFO for the oldest still-queued kick to the same device, so a
burst of kicks from one vCPU (e.g. queued requests outrunning the block
backend) is attributed in the order the device actually services them
rather than by a single overwritable slot.  A multi-vCPU guest ordinarily
runs one virtqueue per vCPU (virtio-blk's queue count tracks the vCPU
count), so scoping the match to the issuing vCPU is also what keeps two
processes' concurrent disk I/O from cross-attributing — the device token
alone does not distinguish separate queues on the same device.  Under
the default virtio ioeventfd fast path the kick is serviced without
entering ``virtio_queue_notify`` in vCPU context, so the records fall
back to positional; run the traced virtio-blk device with
``ioeventfd=off`` (alongside no iothread) for exact attribution.

The captured owner is only as precise as the per-vCPU kernel-mode
ownership model every kernel basic block already uses (see
:ref:`single-address-space`): it comes from whichever thread most
recently entered the kernel on the kicking vCPU, which is correct while
that thread stays on one vCPU and has no clean answer once the guest
scheduler migrates it mid-syscall.  A concurrent multi-process exact-
attribution guest therefore needs each traced process pinned to its own
vCPU (``taskset``/``isolcpus``, or ``sched_setaffinity`` inside the
workload) — the same confinement a single pinned process already needs
for clean kernel-code attribution — not merely ``ioeventfd=off``.  See
:doc:`quickstart` for the canonical configuration.

The **disk block number** is the request's byte offset within the backing
image divided by the block layer's 512-byte sector unit (`block = offset
>> 9``); ``bytes` is the transfer length (0 for a flush barrier).  There is
**no explicit blocking flag**: a consumer derives whether a request
blocked the issuer from the positional distance between its START and STOP
(adjacent, with no traced work between, means the issuer blocked to
completion — e.g. an ``O_DIRECT``/``O_SYNC`` transfer).  These records are
**correct-path only**: a speculative (wrong-path) doorbell store is
sandboxed and reaches no device model, so a wrong-path excursion never
mints a request.

4.2 BODY_TAG_ENTRY
^^^^^^^^^^^^^^^^^^

Each entry records one contiguous run of a correct-path basic block
and its optional wrong-path chain.

::

   +--------------------------------------------------+
   | tag = 1                         u8               |
   | template_id_delta               SLEB             |
   |   current_template_id - previous_entry_template  |
   +--------------------------------------------------+
   | cp_delta_section                section          |
   |   per-instruction records, then this block's     |
   |   block-level records at BLOCK_POS (§5.7)        |
   +--------------------------------------------------+
   | wp_chain_section                section          |  only if CST_FLAG_WP
   +--------------------------------------------------+

The entry has exactly two payload members after the template delta,
and one of them is conditional.  There is no per-entry trailer and no
side-section: a fact about the block travels as a field-delta record
inside ``cp_delta_section`` exactly as a fact about an instruction
does, so a block with nothing to declare beyond its instructions pays
nothing for the possibility.

``previous_entry_template`` starts at 0 and updates after each CP entry.
The current guest-thread ID comes from the most recent
``BODY_TAG_THREAD_SWITCH`` record and the current asid index from the most
recent ``BODY_TAG_ASID_SWITCH``; because the body opens with an
``(asid, thread)`` declaration (§4.1a, §4.1), an ENTRY is always preceded
by both, and every entry carries a well-defined ``(asid, thread)`` context.

4.2a Executed Range and Program Order
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An entry declares which instructions of its template it executed.  The
declaration is the half-open range ``[bb_start, bb_stop)``, carried by
the two block-level field-IDs ``CST_FID_BB_START`` and
``CST_FID_BB_STOP`` (§5.7) with baseline defaults ``0`` and the
template's ``num_insns``, so an entry that ran the whole block declares
nothing and costs nothing.  Both are instruction INDICES into the
template's per-insn descriptor array — the same index space ``ins_pos``
addresses — and ``bb_stop`` is EXCLUSIVE: ``bb_stop == num_insns`` means
the block's last instruction executed.  A well-formed entry satisfies
``0 <= bb_start < bb_stop <= num_insns``; the empty range is not
emitted, because a block that executed nothing is not an event.

``bb_stop`` is the count of leading instructions from ``bb_start`` whose
execution this entry **fully observed** — not the count that retired.
The two differ at the moment execution is taken away mid-block: an
instruction's destination registers are readable only once the next
instruction begins (§5.4), so a run cut short inside an instruction
callback has one retired instruction whose results are not yet
observable, and the entry excludes it.  It reappears as the first
instruction of the continuation, or does not appear at all.  This is
what makes a partial entry honest rather than merely short: every
instruction the range names has its complete memops and its complete
post-execution register state, and the entry asserts nothing whatever
about instructions outside the range.

.. _fmt-end-marker-range:

The END marker is the one stop where this section is normative rather
than merely mechanical, and what it requires is a **whole block**.  A
marker-mode segment's close is deferred to the end of the true BB the
marker fired inside, so the entry publishing that block publishes it
COMPLETE: ``bb_stop`` equals the template's ``num_insns``, the block is
sealed at its own terminating branch, and the firing instruction
together with its block-mates reaches the wire carrying its memory
operands, its register deltas where the trace carries register data,
and the block's resolved branch outcome.  It is an ordinary entry,
produced by the ordinary seal.  In a single-context capture it is the
segment's last entry.

The marker's *position* is carried INSIDE that block rather than by the
range.  A consumer that needs it locates the END sequence in the
template's own instruction bytes — ``insn_bytes`` (§6), and the
sequence's encoding is fixed by the marker contract — and reads the
region of interest as ending at that index.  The instructions at and
after it are the tail of the final block: on the wire because the block
is published whole, and outside the region the marker delimits.  What
ran and where the region ends are two different statements, and the
format carries both rather than collapsing them into one number.

Truncating the final entry at the firing instruction is therefore NOT
conforming.  It publishes a block the guest sealed as one that was
never finished, discards the observations of instructions that
demonstrably executed, and expresses a position the templates section
already carries — buying nothing, at the cost of an unterminated
terminal block and a segment whose final entry is partial for no
architectural reason.  A final entry on this route whose ``bb_stop`` is
less than its template's ``num_insns``, or whose block is not
branch-terminated, means the close landed mid-block: a wire defect, not
a licensed stop point.

A block interrupted and later resumed produces one entry per stretch,
each naming the same ``template_id``:

::

   invocation of BB T (num_insns = 7), a fault at instruction 3:

     entry   template T   [0, 3)     the run before the fault
     entry   handler blocks ...      the excursion, at fault_depth 1
     entry   template T   [3, 7)     the resumption

The instruction the excursion interrupted is the range's exclusive
``bb_stop`` on one entry and its inclusive ``bb_start`` on the next —
one index, named twice, from the two sides.  A consumer rejoins an
invocation by chaining, within one context, each entry naming a
``template_id`` to the next entry naming that same ``template_id``
whose ``bb_start`` equals this one's ``bb_stop``; the chain begins at
an entry whose ``bb_start`` is ``0`` and ends at one whose ``bb_stop``
is ``num_insns``.  A successor whose ``bb_start`` is neither ``0`` nor
the predecessor's ``bb_stop`` is a wire defect, not a licensed
shorthand — the format has no way to skip instructions in the middle
of a block.

One overlap is licensed, at a self-loop.  A bulk-memory self-loop
instruction (``BRANCH_REP`` — :ref:`fanout-self-loop-bbs`) that faults
mid-loop has retired real iterations before the excursion, so the
piece that observed them *includes* the instruction — a prefix
declares ``[0, K+1)`` where ``K`` is the self-loop's index — while the
continuation re-enters the loop at that same instruction and declares
``[K, num_insns)``: the two ranges overlap at exactly the self-loop
instruction, each piece publishing the iterations *it* observed of the
one instruction (the pieces' iteration sequences concatenate to the
unsplit loop).  A loop that faults repeatedly produces one such piece
per excursion that retired iterations, every consecutive pair
overlapping at ``K``.  This is the only licensed overlap: a chaining
consumer reads a successor whose ``bb_start`` is the predecessor's
``bb_stop - 1`` as this rep-split continuation exactly when the shared
instruction is a self-loop terminator, and rejects it anywhere else.

**Order is unconditional.**  Within one ``(thread_id, asid)`` context
the entries are in strict program order with no exceptions.  A block
is emitted when execution leaves it, at the extent that ran, so the
prefix of an interrupted block is on the wire *before* the handler
that interrupted it, and its continuation *after* — the order the
guest ran them in.  Nothing is deferred, reassembled, or placed
retrospectively, and a consumer needs no rule to detect or undo a
reordering.

Normative consequences of a declared range.  The general rule is that
an entry observes exactly the instructions inside its range: a writer
MUST NOT emit a per-instruction record — of any field family — at a
position outside ``[bb_start, bb_stop)``, and a reader MUST reject a
trace that carries one — the record claims an observation of an
instruction the entry itself declares did not complete, and there is
no honest reading of that (§5.7 gives the check's mechanics).  The
block's own records at ``BLOCK_POS`` are outside every instruction
range by construction and are always legal; the range scopes
instruction positions only.  The consequences family by family:

* A memop record MUST NOT appear at an ``ins_pos`` outside
  ``[bb_start, bb_stop)`` — a trace carrying one is rejected — and a
  consumer MUST NOT materialise memops
  for a rangeless position.  A memop an instruction delivered before losing
  the machine — the aborted attempt of a faulted bulk operation, §5.2 —
  belongs to the entry whose range contains that instruction, which is
  the entry that re-executes it, never the entry that stopped before
  it.
* A destination-register snapshot MUST NOT appear at an ``ins_pos``
  outside the range, and a consumer MUST NOT synthesise one.  A
  consumer walking the template to size or index per-instruction state
  clamps that walk to the range; a walk over ``num_insns`` regardless
  is the single mistake this record shape exists to prevent.
* The instruction count an entry contributes to the trace is
  ``bb_stop - bb_start``, not ``num_insns``.
* The branch-outcome singletons (§5.6) appear only on an entry whose
  range contains the terminating branch.

**Fault depth.**  ``CST_FID_BB_FAULT_DEPTH`` (§5.7) is the
exception-nesting depth at which this basic block executed: ``0`` for
ordinary, non-handler code; ``>= 1`` for the code of a
synchronous-fault handler — or, with ``interrupts=1``, an asynchronous-
interrupt handler — that detoured execution at that nesting level.
User-privilege entries always carry depth ``0``: user code is never
handler content.

The nesting is a property of the entry's own ``thread_id``.  Concurrent
threads detour independently, so a consumer reads the depth column per
thread: within one thread's entries the depth steps one level at a time,
into a handler and back out of it, while a peer thread scheduled onto the
same core during that excursion carries its own — normally ``0`` — depth.
Interleaving two threads' entries and reading the column as a single stack
is a consumer error, not a wire property.

The range and the depth together are the whole wire mechanism behind
both system-mode handler-tracing options (see :doc:`reference` for the
full option semantics); neither adds a wire record of its own:

- ``faults=1`` (default) traces a synchronous-fault handler as
  first-class code at its depth, between the interrupted block's
  ranges.  ``faults=0`` excludes the handler from capture instead: the
  interrupted block still emits its ranges, in order, with nothing
  between them and depth ``0`` throughout, so a ``faults=0`` trace
  advertises ``CST_FLAG_FAULT`` yet never emits a depth ``> 0`` entry.
- ``interrupts=0`` (default) excludes an asynchronous interrupt's handler
  excursion entirely.  ``interrupts=1`` traces it instead, at depth
  ``>= 1`` — one level added on top of any live synchronous-fault
  nesting.  An asynchronous interrupt lands on a basic-block boundary,
  so the block it follows is a whole one and no range is split.

See :doc:`architecture`, "Asynchronous interrupts and the two
handler-tracing flags", for the capture-side mechanics behind both options.

**Thread end.**  ``CST_BB_FLAG_THREAD_END`` on an entry states that this
is the last entry its ``(thread_id, asid)`` context contributes to the
segment.  The segment close stamps it on the final entry it emits for a
context — the pending block the close put on the wire at its measured
extent.  Combined with the range it says exactly where that context's
instruction stream stops.  It is a positive marker, not an exhaustive
one: a context whose last entry was already on the wire when the close
arrived (nothing of it was pending) ends with the segment itself and
carries no flag, so a consumer treats the segment boundary as the end
of every context the flag did not already end.  Two close routes end
*every* context that way by construction — the dead-latch (IDLE) close
and the any-context ceiling — because they are raised by a sweep
precisely when the pinned context has stopped executing, so at the
moment they fire nothing of it is pending and the final entry it did
contribute went to the wire through the ordinary seal path, when
nothing could know it was the last.  The flag is not withheld there,
it is unavailable: the fact is retroactive and the entry is already
written.  A segment closed by either route therefore names no context
end at all, and the segment boundary is the whole answer.  In a
user-mode trace,
where a thread index is released on exit and may be reissued to a
thread created later (§4.1), a flagged entry also separates the two
occupants of one index.

4.3 Wrong-Path Chain Section
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The wrong-path chain is a list of speculative basic blocks following
the CP block. Template IDs are delta-coded within the chain.

::

   wp_chain_section payload:

     num_wp : ULEB

     repeat num_wp times:
       wp_template_id_delta : SLEB
       wp_delta_section     : section

Wrong-path field state is its own persistent overlay, not a per-chain
fork: WP records decode by reading the WP overlay first, the CP
overlay on miss, then the template default, and their updates land in
the WP overlay only, which persists for the whole body stream (§5).  A
chain therefore never modifies correct-path state, and a template's
speculative observations carry across chains rather than being re-paid
per entry.

``num_wp`` is a plain block count with nothing packed into it.  Each
chain block's ``wp_delta_section`` is an ordinary field-delta section
(§5) and therefore carries that block's own block-level records at its
own ``BLOCK_POS`` — its executed range and, where there is something to
say, its ``CST_FID_BB_FLAGS`` and ``CST_FID_BB_FAULT_INSN`` (§4.4).  A
speculative block is described in the same terms as a correct-path
one, by the same records, and a chain whose blocks all ran whole and
reported nothing costs the chain header and the per-block template
deltas alone.

4.4 Wrong-Path Block Events
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Two conditions a wrong-path excursion can meet are named on the wire,
and both are block-level facts carried by the block they describe:
``CST_BB_FLAG_SYNTHETIC_FAULT`` (with the sibling
``CST_FID_BB_FAULT_INSN`` naming the instruction) and
``CST_BB_FLAG_TRANSLATION_UNAVAIL``.  Each rides its own chain block's
``wp_delta_section``, at that block's ``BLOCK_POS``, as an ordinary
field-delta record (§5.7).  There is no side-section and no index
space: a block that has nothing to report emits no record, which is
what a sparse field does natively, and a block that does costs one
record.

The flags delta-persist per ``(template_id, BLOCK_POS,
CST_FID_BB_FLAGS)`` like every other cell, so a writer MUST emit a
record whenever a block's flags differ from that cell's current value —
including back to ``0`` on the next clean execution of a template that
reported something last time.

One condition belongs to no block and is therefore carried by the
correct-path entry that owns the excursion:
``CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL`` on the CP entry says the
excursion was kicked but its first fetch could not complete, so the
chain is empty (``num_wp == 0``).  This makes the architecturally
faithful 0-block chain explicit rather than indistinguishable from an
entry whose wrong path was never simulated.  Putting it on the CP
entry is what lets the wire describe an empty chain at all: there is
no block to hang it on.

``CST_BB_FLAG_TRANSLATION_UNAVAIL`` marks its block as the excursion's
**last**: the next speculative fetch's target could not be translated —
un-resident code under demand paging, a refused garbage region, a
speculative fetch crossing the privilege boundary the excursion
launched at, or the host's speculative code buffer exhausted — so the
walk stops there.  It is the sole stop the wire names, and it is set
on the last block that did complete, not on a block that did not
exist.

``CST_BB_FLAG_SYNTHETIC_FAULT`` marks a wrong-path block that contains a
**synthetic-data fault** at the instruction index its sibling
``CST_FID_BB_FAULT_INSN`` record names.  On a mispredicted path
no instruction ever retires, so a back-end synchronous fault a
speculative instruction would raise is never actually taken by a real
core — the branch-mispredict squash kills the path before commit.  The
tracer models this rather than truncating: a speculative memory access
to an absent/unreadable page is served a deterministic pseudo-random
placeholder value (keyed on the guest address, so the same bad address
always reads the same bytes), the instruction is marked here, and the
excursion **continues** on that placeholder to the ``wpdepth`` budget.
Everything downstream of the marked instruction is therefore synthetic;
a consumer treats the marked instruction's result — and any value
derived from it — as speculative filler that never architecturally
retires.

A non-memory synchronous fault carries the same event with the same
meaning.  An execution-time exception (arithmetic overflow or
divide-by-zero, illegal opcode, alignment, a conditional trap) or a
syscall-class kernel entry (``syscall`` / ``int`` / ``svc`` /
``ecall`` / ``break``) leaves speculative execution the only way it
can, by raising — but nothing retires on a wrong path, so a real core
never takes it either.  The tracer marks the block, skips the raising
instruction, and re-dispatches at that instruction's architectural
fall-through, taking the unfollowable kernel edge as the taken side of
an ordinary branch and continuing on the not-taken side to the
``wpdepth`` budget, exactly as the memory case continues.  The skipped
instruction's destinations are left stale — the same deterministic
placeholder — so its dependents still execute.

``CST_BB_FLAG_SYNTHETIC_FAULT`` is therefore an **attribute** of a
block — "this block consumed synthetic data" — and never a terminator.
A reader MUST NOT infer termination from it, including when it lands
on the chain's last block, where it is a coincidence rather than the
cause.  Only a **front-end** fault
(``CST_BB_FLAG_TRANSLATION_UNAVAIL``, above) stops an excursion, and it
is the sole stop the wire names.

For the same reason ``CST_FID_BB_FAULT_INSN`` is **not** the block's
``bb_stop``.  The excursion continues past the marked instruction on
placeholder data, so the block executes to its end and its range says
so; folding the marked index into ``bb_stop`` would assert a
termination the format explicitly denies.  The two indices are
independent and a block routinely carries both.

A chain never *attributes* past its ``wpdepth`` budget.  The walker
finishes the block in flight when the budget runs out — a speculative
block is simulated whole to its branch terminator — but the last
block's record then carries its own executed range, cut at exactly the
instructions that fit: the chain's ranges sum to precisely ``wpdepth``,
and the cut block's terminating branch sits outside its range, so no
branch-outcome records ride it.  A fault-marked block is exempt from
the cut (``CST_FID_BB_FAULT_INSN`` must stay addressable inside the
range, and the fault carve-out already excludes such chains from
exactness claims).

An excursion can nonetheless end short of its ``wpdepth`` budget with
nothing on the wire to say so.  Alongside the skip-and-continue path
the tracer keeps containment bails — a delay-slot branch whose slot
never landed, a fall-through that is itself an already-poisoned
target, and a forward-progress guard that trips when the same PC
re-faults sixteen times — each of which ends the excursion at the last
sealed block.  None of them is signalled.  A chain whose ranges sum to
exactly the ``wpdepth`` recorded in the header's ``command`` string
(§3) spent its budget; a shorter fault-free chain hit a bail, and that
comparison is the only way to tell.

The unfetchable first target that
``CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL`` names arises for the same
reasons as the mid-chain case, plus one of its own: on a
software-managed-TLB ISA the refill exception cannot be taken
speculatively, so real hardware would also fetch nothing there.

4.5 BODY_TAG_IFRAME
^^^^^^^^^^^^^^^^^^^

An IFRAME is a redundant absolute-encoded copy of the immediately-
preceding ``BODY_TAG_ENTRY`` body record. The writer emits it at an
arbitrary cadence (controlled by the ``iframe_rate`` plugin option, but
the wire format does not record the rate); decoders may use it to
cross-check that their delta-replay reconstructed the same view the
writer had, or skip it entirely.

::

   +--------------------------------------------------+
   | tag = 3                         u8               |
   | cp_delta_section                section          |
   | wp_chain_section                section          |  only if CST_FLAG_WP
   +--------------------------------------------------+

The IFRAME inherits the ``template_id`` of the preceding ENTRY (no
``template_id_delta`` is encoded). Inside, every field-delta record is
encoded against ``template_default`` rather than against the persistent
overlay state, so the decoded value is absolute — block-level records
included: the whole ``BLOCK_POS`` row is part of what an IFRAME
reproduces, so a partial ENTRY's IFRAME states ``bb_start`` and
``bb_stop`` absolutely, a flagged one re-states its flags and depth,
and an ENTRY that ran its block whole emits neither range record (both
already equal their defaults).  The reconstructed range
is part of what must match, and it bounds what the IFRAME's own
register and memop reconstruction covers, exactly as it bounds the
ENTRY's.  When the CP-side
triggers an IFRAME, the entire body record is re-emitted in IFRAME
mode — including every WP-chain entry attached to that CP block; WP
entries are never IFRAME'd independently of their owning CP entry.

IFRAMEs MUST NOT advance ``previous_entry_template`` and MUST NOT update
the persistent ``cp_field_state`` / ``wp_field_state`` overlays — they
are pure validation/resync redundancy. The next ``BODY_TAG_ENTRY``
continues from where the preceding regular ENTRY left off.

4.6 BODY_TAG_REGFILE
^^^^^^^^^^^^^^^^^^^^

A ``BODY_TAG_REGFILE`` record carries a per-thread initial register-file
snapshot: the architectural register values for one thread at the
point its execution in this segment begins. It seeds a consumer's
register model so that destination-register snapshots (§5.4) and
metaflags reconstruct absolute values. It is not counted in
``num_entries`` and does not advance any body counter.

::

   +--------------------------------------------------+
   | tag = 4                          u8              |
   | thread_id                        ULEB            |
   | n_present                        ULEB            |
   | repeat n_present times:                          |
   |   gen_id       u8     GenericRegId; resolve via   |
   |                       the `reg` map               |
   |   width        u8     snapshot byte count          |
   |   bytes[width]        raw, little-endian order     |
   +--------------------------------------------------+

A producer that does not capture initial register state emits no
``BODY_TAG_REGFILE`` records; their absence is not an error.

5. Field-Delta Sections
~~~~~~~~~~~~~~~~~~~~~~~

Every CP block and every WP block has one field-delta section. This is
the sparse update stream for dynamic memory addresses, memory values,
register values, memory-operation counts, and instruction metadata.

::

   delta_section payload:

     n_records : ULEB

     repeat n_records times:
       ipos_delta : ULEB        running ipos += ipos_delta
       fid        : ULEB        resolve through the "field_id" map
       delta      : SLEB_WIDE   scalar delta; plus a trailing
                                ext_payload:ULEB only when fid resolves
                                to CST_FID_EXTENDED

The running ``ipos`` cursor is **section-local**: decoders initialise
``ipos = 0`` at the start of every delta section (one per CP block, one
per each WP chain entry, one per IFRAME) and add ``ipos_delta`` from each
record. It is **not** carried across sections — there is no rolling
per-BB or per-template ipos. The persistent state that *does* carry
across sections is the per-template field-state cell keyed by
``(template_id, ipos, field_id)`` (see below); the wire-level ``ipos``
cursor is just the in-section pointer used to address those cells.

Positions ``0 .. num_insns-1`` address the template's instructions.
The one position above them, ``ipos == num_insns``, addresses the
**block itself** and is written ``BLOCK_POS`` throughout this spec; it
carries the block-level fields of §5.7 and nothing else.  No
instruction occupies it, so ``(template_id, BLOCK_POS, field_id)`` is
an ordinary cell in the same key space with the same lifetime and the
same overlay rules — the block dictionary is the instruction
dictionary, addressed one position further along.  ``num_insns`` here
is always the *referenced template's own*: ``BLOCK_POS`` is a
per-template position, not a constant of the format, and a section is
sized from the template the owning record names — never from another
revision at the same ``start_pc`` (§5.7, Step 0).

Writers MUST emit records in non-descending ``(ipos, fid)`` order.
When two records describe the same position, the later record has
``ipos_delta = 0``.  Half of the rule is enforced by the encoding
itself — ``ipos_delta`` is unsigned, so a descending position cannot
be expressed — while the ``fid`` order within one position is the
writer's duty alone.  Because ``BLOCK_POS`` is the highest position a
section has, the sort places a section's block-level records last,
after every per-instruction record, at the cost of one ``ipos_delta``
and with no ordering rule of their own.  The consumer rule that
follows is stated in §5.7: an entry's meaning is defined by the whole
section, so a consumer MUST apply every record of a delta section
before interpreting the entry — the executed range arrives last, after
the per-instruction records it scopes, and the two-pass shape the
delta model already requires has it in hand before it is needed.

Every record is a scalar delta record:

::

   scalar_delta := SLEB_WIDE

   delta = current_value - baseline, modulo 2**512
   current_value = (baseline + delta) mod 2**512

Scalar values are little-endian unsigned integers with a 512-bit cap.
The two's-complement modular delta is emitted as one signed LEB value.
Small 32-bit and 64-bit values still encode as short LEBs; wide vector
register and memory values can occupy up to 512 bits.  Every body
record is a scalar delta — there is no raw-vector / ``EXTRA_*`` record
shape; all memops are addressed through the slotted families.

Scalar delta records update persistent field state. State is keyed by
``(template_id, ins_pos, field_id)``:

::

   first observation:
     baseline = template_default(template_id, ins_pos, field_id)

   later observations:
     baseline = last_current_value_for_same_key

   decode:
     current = (baseline + delta) mod 2**512

``template_default`` is a function of all three key components, and it
is not always a constant.  For most families it is zero; for the
``INSN_*`` metadata family it is the referenced template's own per-insn
descriptor value; and for ``CST_FID_BB_STOP`` at ``BLOCK_POS`` it is
the referenced template's own ``num_insns`` (§5.7) — a baseline that
differs from template to template exactly as the metadata family's
does.  A decoder that implements ``template_default`` as a lookup
against the referenced template, rather than as a table of constants,
covers all three cases with one rule.

CP and WP each have their own overlay of ``(template_id, ins_pos, field_id)``
→ value, both persisting for the whole body stream. WP records lookup
the WP overlay first, fall back to the CP overlay on miss, then to
the field's template default. Updates always write to the active
overlay (CP overlay for CP records, WP overlay for WP records); the
WP overlay never modifies CP state, so CP reconstruction is
unaffected by speculative side effects.

::

   CP entry N:

     cp_state before ---- cp_delta_section ----> cp_state after
     wp_state before ---- (unchanged on CP)       wp_state before
                                 |                       |
                                 +-- WP chain ---+       |
                                                 |       |
                                 wp_state(N-1) --+-------+
                                                 |
                                                 +-- wp block 0 deltas
                                                 |   (lookup wp first,
                                                 |    cp on miss)
                                                 +-- wp block 1 deltas
                                                 |
                                                 +-- wp_state(N) (kept)

The WP overlay is persistent across chains: hot WP templates
visited from many CP entries delta against their prior WP-observed
value instead of paying the first-observation cost on every chain.
The CP overlay is unaffected by speculative records.

5.1 Field-ID Space
^^^^^^^^^^^^^^^^^^

Field IDs are ULEB128 on the wire (Step 6.9).  Numeric IDs are
**not** pinned in the format spec; the header's ``field_id`` encoding
map (Reference §3.1) carries the (id → name) pair for every field
the trace uses, and decoders MUST look up fields by name there.
This section describes the field families the writer emits and the
encoding-cost intent behind the writer's ID assignment.

Field families (one canonical name each):

* ``CST_FID_N_LOADS`` — count of valid load slots for this insn
  execution.  Encoded as a non-negative scalar delta against the
  prior observation of ``(template_id, ins_pos)``; baseline default
  is zero.  Always emitted on entries whose insn has memops.  It
  is a count of *slots present in this entry*, so it never exceeds
  ``CST_FID_SLOT_COUNT``: an instruction that performs more loads
  than the wire has slots for reports the ceiling, and a decoder can
  read ``N_LOADS`` slots unconditionally.  ``LOAD_ADDR{k}`` for
  ``k ≥ N_LOADS`` is meaningless — the delta stream leaves whatever
  the previous observation of that slot wrote.

* ``CST_FID_N_STORES`` — analogous, for stores.

* ``CST_FID_METAFLAGS`` — canonical Z/N/C/V/P byte (see §2).
  Gated on ``CST_FLAG_REG_DATA``; only emitted for insns whose
  template writes the ISA's integer-flags register, and only on
  ISAs that have one (x86, AArch64).

* ``CST_FID_LOAD_ADDR{k}`` for ``k ∈ [0, CST_FID_SLOT_COUNT)`` —
  load virtual addresses, indexed by memop slot.  Names are
  ``CST_FID_LOAD_ADDR0``, ``CST_FID_LOAD_ADDR1``, ... — the encoding
  map carries one entry per slot, and decoders look each up by
  name.  Address bits beyond u64 are silently truncated; address
  values are emitted as scalar deltas.

* ``CST_FID_STORE_ADDR{k}`` — analogous, for store addresses.

* ``CST_FID_LOAD_DATA{k}`` — load values, gated on
  ``CST_FLAG_MEM_DATA``.  Up to 512 bits per slot (vector-register
  loads), emitted via the ``SLEB_WIDE`` scalar-delta path.

* ``CST_FID_STORE_DATA{k}`` — analogous, for store values.

* ``CST_FID_DST_REG{k}`` — destination-register post-execution
  snapshots, indexed by the template's ``dst_regs`` array position.
  Gated on ``CST_FLAG_REG_DATA``.  Source-register values are not
  emitted on the wire — consumers reconstruct them from a regfile
  that the initial-state REGFILE records and the DST_REG snapshots
  collectively define.

.. _fmt-width-families:

* **Width families** — the byte width of each captured value, for
  value-prediction consumers that need to know how many bytes a
  predicted register or memory value covers.  The width is not
  recoverable from the value itself (the ``SLEB_WIDE`` encoding is
  magnitude-suppressed, with no length prefix) and is not static
  across ISAs (RISC-V V element width is the runtime ``SEW``; SVE
  register width follows the vector length), so it is carried as its
  own per-slot field:

  * ``CST_FID_LOAD_SIZE{k}`` / ``CST_FID_STORE_SIZE{k}`` — access
    byte width of load / store memop slot ``k``.  Gated on
    ``CST_FLAG_MEM_DATA`` (they ride with ``LOAD_DATA`` / ``STORE_DATA``).
  * ``CST_FID_DST_REG_WIDTH{k}`` — write byte width of
    destination-register slot ``k``.  Gated on ``CST_FLAG_REG_DATA``.

  Each is a per-``(template_id, ins_pos, slot)`` sparse scalar with
  baseline default zero, so a fixed-width access emits one record at
  first observation and zero bytes thereafter, while a width that
  varies (RVV ``SEW`` / SVE ``VL`` changes) emits a delta only when it
  changes.  Values are clamped to ``CST_MAX_WIDE_BYTES``.  These
  families post-date the others; a trace produced without them is
  well-formed and decoders treat their absence as "width not
  captured" — with one exception, which is a property of the opcode
  and not of the field: a memop belonging to ``GEN_OP_PREFETCH``,
  ``GEN_OP_CACHE_FLUSH`` or ``GEN_OP_TLB_FLUSH`` is address-only and
  its width is ``0`` by construction.  See
  :ref:`the synthesized memop <fmt-synthetic-ea-width>`.

* **Vector lane-mask families** (four, one slot per operand, gated on
  the per-insn ``CST_INSN_FLAG_VEC`` bit — see §6 *Vector lane masks*):

  * ``CST_FID_SRC_LANE_MASK{k}`` — for source-register slot ``k``
    (parallel to the template ``src_regs`` array): bit ``j`` set iff lane
    ``j`` of that source register participates as an input this
    execution.
  * ``CST_FID_DST_LANE_MASK{k}`` — for destination-register slot
    ``k``: bit ``j`` set iff lane ``j`` of that destination is produced
    this execution.  Need not equal the src masks.
  * ``CST_FID_LOAD_DATA_LANE_MASK{k}`` — for load memop slot ``k``:
    bit ``j`` set iff lane ``j`` of the value-receiving vector register
    takes its value from this particular load.
  * ``CST_FID_STORE_DATA_LANE_MASK{k}`` — for store memop slot ``k``:
    bit ``j`` set iff lane ``j`` of the source vector register is drained
    by this particular store.

  Each is a per-``(template_id, ins_pos, slot)`` sparse field whose
  baseline default is zero, emitted as a scalar delta exactly like
  the other slotted families — so a uniform mask costs one record at
  first observation and zero bytes thereafter, while a mask that
  moves per execution (RISC-V V ``vl``, gather/scatter memop fan-out)
  emits a delta only when it changes.  Mask width is up to 64 lanes
  (ULEB on the wire; the common 2/4/8/16-lane cases stay one byte).

* **Physical-page families** (two, one slot per memop, gated on the
  ``CST_FLAG_PHYSADDR`` header bit — system-mode ``physaddr=1`` only):

  * ``CST_FID_LOAD_PPAGE{k}`` — for load memop slot ``k``: the physical
    PAGE base of the access, i.e. its physical address masked to
    ``cst_wire::PPAGE_SHIFT`` (4 KiB).  Consumers rebuild the full physical
    address as ``ppage | (vaddr & PPAGE_OFFSET_MASK)`` — see §5.3.1.
  * ``CST_FID_STORE_PPAGE{k}`` — analogous, for store memop slot ``k``.

  Each is a per-``(template_id, ins_pos, slot)`` sparse scalar with baseline
  default zero, delta-encoded exactly like ``LOAD_ADDR`` / ``STORE_ADDR``.
  These carry only *lazily-observed* translations: a page's mapping records
  once on the first touch and then costs **zero bytes** while it holds — an
  in-page walk (offset changes, page base does not) emits nothing, and an
  OS remap (copy-on-write, page migration) self-corrects with a single
  delta on the next access.  The families do **not** encode the page table;
  they are a running observation of the translations the traced accesses
  actually used.  A memop with no observable RAM translation — user mode,
  MMIO, or a garbage-filled wrong-path access to an absent page — emits no
  record for that slot, so the running value simply holds the last real
  translation.  These families post-date the others; a trace produced
  without ``physaddr=1`` names neither and is byte-identical to one from a
  writer that predates them.

* **Instruction-metadata singletons** (cold; emitted only when
  the dynamic execution differs from the template baseline):
  ``CST_FID_INSN_BYTES_LO``, ``CST_FID_INSN_BYTES_HI``,
  ``CST_FID_INSN_OPCODE``, ``CST_FID_INSN_BRANCH_TYPE``,
  ``CST_FID_INSN_FLAGS``, ``CST_FID_INSN_IMMEDIATE``,
  ``CST_FID_INSN_SIZE``.

* ``CST_FID_EXTENDED`` — reserved escape; reserve only.  The
  scalar-delta byte after this field-id's record is followed by
  one extra ULEB whose value is reserved.

* **Block-level singletons** (five; addressed at ``BLOCK_POS`` rather
  than at an instruction — see §5.7 for the full contract):

  * ``CST_FID_BB_START`` — index of the first instruction of the
    template this entry executed.  Baseline default ``0``.
  * ``CST_FID_BB_STOP`` — one past the index of the last instruction
    this entry fully observed.  Baseline default is the template's
    ``num_insns``, the only per-template baseline outside the
    instruction-metadata family.
  * ``CST_FID_BB_FLAGS`` — bitmask of ``CST_BB_FLAG_*`` bits, resolved
    through the ``bb_flag`` map (§2).  Baseline default ``0``.
  * ``CST_FID_BB_FAULT_DEPTH`` — exception-nesting depth this block
    executed at (§4.2a).  Baseline default ``0``; gated advisorily on
    ``CST_FLAG_FAULT``.
  * ``CST_FID_BB_FAULT_INSN`` — instruction index of a wrong-path
    block's synthetic-data fault (§4.4).  Baseline default ``0``,
    meaningful only when ``CST_BB_FLAG_SYNTHETIC_FAULT`` is set in the
    same block's flags.

* **Branch-outcome singletons** (two; always advertised — see §5.6):

  * ``CST_FID_BRANCH_TAKEN`` — ``1`` if the BB's terminating branch
    transferred control (taken), ``0`` if it fell through.
  * ``CST_FID_BRANCH_TARGET`` — the branch's landing PC encoded as a
    **signed displacement** from the branch instruction's own PC
    (``successor − branch_pc``), *not* the raw PC.  A reader reconstructs
    the absolute successor as ``branch_pc + displacement``.  When not
    taken this displacement resolves to the fall-through, so the field
    is the architectural successor either way.

  Both ride the terminating branch instruction's ``ins_pos`` (like
  ``METAFLAGS``), with baseline default zero, and appear on a
  branch-terminated block on both the correct path and every wrong-path
  chain block (a page-split continuation carries neither).  Encoding the
  target as a displacement keeps even a first sighting a small sleb —
  a direct branch's displacement is tiny, an indirect target far smaller
  than a full 64-bit PC.  Their numeric IDs sit after the physical-page
  block, so a trace that predates them names neither; a post-branch
  writer always advertises both.  See §5.4 for the full contract.

**Layout intent (non-normative).**  The writer assigns numeric
IDs so the hot fields — slot counts, metaflags, and low-slot
memops + destination snapshots — collectively occupy IDs ``< 128``
and therefore emit as a single ULEB byte.  High-slot families,
the cold instruction-metadata singletons and the block-level
singletons fall into the 2-byte ULEB range (IDs 128..16383).
The block-level names' numeric placement is purely a byte-cost
choice: a section's block records sort last because ``BLOCK_POS``
is its highest *position* (§5), a structural fact that no ID
assignment could change.  A future writer may
re-shuffle within these constraints (e.g., promote a different
hot field into the 1-byte range based on observed frequency)
without bumping ``CST_MAGIC``; readers consume the per-trace
encoding map and stay correct.

The slot-family layout is **interleaved by slot** (slot ``k`` of
every family is co-located in the ID space) rather than
**family-then-slot** (all of one family before the next).  This
keeps low slots of every family in 1-byte territory and yields
strictly fewer total bytes than the alternative on every
realistic workload — see §5.2.

5.2 Memory Counts and Addresses
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``N_LOADS`` and ``N_STORES`` are ordinary sparse fields. Their baseline
defaults are zero. The writer derives current values by counting QEMU
memory callbacks for each instruction execution; opcode tables and
Capstone operand flags do not define these counts.

Three opcodes — ``GEN_OP_PREFETCH``, ``GEN_OP_CACHE_FLUSH``, and
``GEN_OP_TLB_FLUSH`` — describe instructions that QEMU's TCG translates
to no memory op (software prefetch hints, cache-line clean / flush /
invalidate, TLB-entry invalidate). The writer synthesises a load
memop for these by decoding the Capstone operand at translation time
and reading base / index register values at execution time, computing
``ea = base + index_term + disp``, where ``index_term`` is
``index << shift_amount`` for an addressing form that shifts the index
(the AArch64 register form) or ``index * scale`` for one that scales it
(the x86 SIB form) — the two are mutually exclusive. The synthesized
EA appears in the same ``LOAD_ADDR[0]`` slot as a regular load and
contributes to ``N_LOADS``. Opcode classification (PREFETCH / CACHE_FLUSH /
TLB_FLUSH) carries the semantic distinction; consumers that simulate
prefetch hints, cache-line evictions, or TLB shootdowns should
dispatch on the opcode rather than treating the EA as a normal load.
Instructions in these classes that have no memory operand (e.g. x86
``WBINVD``, AArch64 ``IC IALLU``) emit no synthesized address and stay
classified under ``GEN_OP_FENCE``.

.. _fmt-synthetic-ea-width:

The synthesized memop is **address-only**, and its width is ``0``
""

A synthesized memop carries an address and no data. Its
``CST_FID_LOAD_SIZE0`` is ``0`` — **by construction, and not because a
width was omitted**. No data crosses the guest/host interface for any
instruction in these three classes, so there is no value to size: the
architecture-visible effect is on a cache line, a translation entry, or
nothing at all.

The extent of such an operation is a property of the **cache being
modelled**, not of the instruction, and a trace cannot state it without
picking somebody's geometry:

* The guest's own architected line size is a per-CPU-model constant that
  varies. Under ``qemu-aarch64`` the default ``max`` model reports
  ``CTR_EL0 = 0x80038003`` — a 32-byte ``DminLine`` and ``IminLine`` —
  while ``cortex-a57`` reports 64 bytes and ``a64fx`` reports 256.
  Recording it would make the meaning of a trace depend silently on
  ``-cpu``.
* Even within one operation class the granule is not one number:
  AArch64 D-side maintenance uses ``CTR_EL0.DminLine`` and I-side
  maintenance ``CTR_EL0.IminLine``, which are separate fields;
  ``GEN_OP_TLB_FLUSH`` acts on a *page* whose size follows the runtime
  translation granule; and a prefetch's access size is
  IMPLEMENTATION DEFINED by the architecture.
* QEMU performs no access to measure. AArch64 ``DC CVAU`` / ``DC CVAC``
  / ``DC CIVAC`` are ``ARM_CP_NOP``, ``IC IVAU`` is ``ARM_CP_NOP``
  except under ``CONFIG_USER_ONLY`` (where it invalidates a translation
  range and touches no data), MIPS ``SYNCI`` lowers to a bare
  ``DISAS_STOP``, and x86 ``PREFETCH*`` translates to nothing.

**What a consumer does instead, without guessing.** The address in
``LOAD_ADDR[0]`` is the raw effective address the guest computed — it is
*not* rounded down to a line — so a consumer aligns it to the geometry
it is itself simulating, which is the only geometry that can be correct
for it. The discriminator is the **opcode**, which is present in every
trace: ``CST_FID_LOAD_SIZE0`` rides with ``LOAD_DATA`` and so is absent
altogether from a trace produced without ``memdata``, and therefore may
never be used to tell an address-only memop from a sized one. The rule
is:

  ``opcode ∈ {GEN_OP_PREFETCH, GEN_OP_CACHE_FLUSH, GEN_OP_TLB_FLUSH}``
  → the memop in ``LOAD_ADDR[0]`` is an address, its width is
  meaningless, and no ``LOAD_DATA`` is published for it.

  any other opcode → a width of ``0`` means the width was not captured,
  per :ref:`the width families <fmt-width-families>`.

The exact operation — a D-side clean versus an I-side invalidate, both
of which classify as ``GEN_OP_CACHE_FLUSH`` — is recoverable from the
instruction bytes the block template carries, for a consumer that needs
to distinguish them.

LOAD / STORE as fall-through classifications
""""""""""""""""""""""""""""""""""""""""""""

``GEN_OP_LOAD`` and ``GEN_OP_STORE`` are fall-through buckets that say
"data motion happens, nothing else does." When an instruction does
something *more* than load-store-of-data, the opcode reflects that
more specific operation:

* **Atomic RMW where the data is mutated by an arithmetic op** —
  AArch64 ``LDADD`` / ``LDCLR`` / ``LDEOR`` / ``LDSET``, RISC-V ``AMOADD`` /
  ``AMOAND`` / ``AMOOR`` / ``AMOXOR``, x86 ``XADD`` — classify as the
  arithmetic op (``INT_ADD`` / ``AND`` / ``XOR`` / ``OR``) with ``MF_ATOMIC``.
  The load and store are incidental to the modify.
* **Atomic exchange** — AArch64 ``SWP`` / ``CAS{P}``, RISC-V ``AMOSWAP`` /
  ``AMOCAS``, x86 ``XCHG`` / ``CMPXCHG`` — classify as ``XCHG`` with
  ``MF_ATOMIC``. ``XCHG`` is reserved for instructions whose semantic IS
  swap.
* **Exclusive-monitor primitives that are individually just a tagged
  load or tagged store** — MIPS ``LL`` / ``SC``, RISC-V ``LR`` / ``SC``,
  AArch64 ``LDXR`` / ``LDAXR`` / ``STXR`` / ``STLXR`` — classify as
  ``LOAD`` / ``STORE`` with ``MF_ATOMIC``. The monitor is a side effect
  on hardware state; the data is unmodified.
* **Loads / stores with implicit pointer arithmetic** — x86 string
  ops ``LODS`` / ``STOS`` / ``INS`` / ``OUTS`` advance ``RSI``/``RDI`` by the
  operand size on every iteration, so classify as ``INT_ADD`` even
  though the data motion is still occurring. AArch64 writeback
  ``LDR`` / ``STR`` / ``LDP`` / ``STP`` (``[Xn]!`` or ``[Xn], #imm``) are the
  ARM equivalent — Capstone collapses them with the non-writeback
  forms, so the per-ISA refiner detects the implicit base-register
  write at translation time and reclassifies to ``INT_ADD``.
* **``MOV`` / ``CMP`` are not fall-through** — they describe specific
  operations (data motion, comparison) and stay even when there is
  a side-effect pointer advance: x86 ``MOVS{B,W,Q}`` keeps ``MOV``,
  ``CMPS{B,W,Q}`` / ``SCAS{B,W,D,Q}`` keep ``CMP``.
* **Load-acquire / store-release** (AArch64 ``LDAR`` / ``STLR`` /
  ``LDAPR`` / ``LDLAR`` / ``STLLR``, RISC-V ``.aq`` / ``.rl`` variants when
  paired with ``LR`` / ``SC``) — memory ordering hints, not atomic
  primitives in the RMW sense. Classified as plain ``LOAD`` /
  ``STORE`` (without ``MF_ATOMIC``); the ordering metadata is not
  currently surfaced on the wire.

Reserved fallback latency opcodes
"""""""""""""""""""""""""""""""""

The opcode space carries six reserved IDs the in-tree tracer never
emits: ``GEN_OP_INT_ALU_SHORT``, ``GEN_OP_INT_ALU_LONG``,
``GEN_OP_FP_ALU_SHORT``, ``GEN_OP_FP_ALU_LONG``, ``GEN_OP_VEC_ALU_SHORT``,
and ``GEN_OP_VEC_ALU_LONG``. They exist
as a coarse fallback for external trace writers that lack ISA-specific
opcode metadata: SHORT is a single-cycle ALU op; LONG is anything
that occupies a long-latency unit (multi-cycle multiplier, divider,
vector pipe, etc.). Consumer code should handle them so foreign
traces remain decodable; in-tree traces always carry the more specific
opcode classifications above.

.. _fanout-self-loop-bbs:

Bulk-memory self-loop BBs
"""""""""""""""""""""""""

``BranchType`` carries a dedicated value ``BRANCH_REP`` (resolved
through the ``branch_type`` map) for a template instruction whose
memory fan-out is bounded by nothing but a register value.  Two
families qualify, and no other instruction on any supported ISA does:

* **x86 REP / REPNZ string operations** — MOVS / STOS / LODS / CMPS /
  SCAS / INS / OUTS, identified from the Capstone prefix detail.  The
  count register bounds the loop.
* **AArch64 FEAT_MOPS bulk copy and set** — CPYP / CPYM / CPYE,
  CPYFP / CPYFM / CPYFE, SETP / SETM / SETE, SETGP / SETGM / SETGE and
  their option-suffixed variants.  The size register Xn bounds the
  transfer, and glibc routes every ``memcpy`` / ``memmove`` / ``memset``
  through them on a FEAT_MOPS guest.

Both are emitted as self-looping conditional branches: target = the
instruction's own PC, fall-through = the next PC.  Consumers that model
branch behaviour should treat ``BRANCH_REP`` distinctly from
``BRANCH_COND_DIRECT``:

* The taken-target is always the insn's own PC, so a predictor
  does not need to track target diversity for these branches.
* The not-taken path exits the loop (x86: ECX == 0 or a REPZ/REPNZ
  comparison terminator; MOPS: the size register is exhausted).

The body stream models each iteration of the loop as its own true-BB
visit:

1. The BB that *enters* the loop ends at the fan-out instruction.  Its
   body entry carries iteration 1's memops on that insn's slot,
   alongside the preceding setup insns' regular state.
2. Iterations 2..N each emit a separate body entry on a 1-insn
   self-loop sub-template.  The sub-template's single instruction
   is the fan-out insn itself with ``BRANCH_REP`` and `start_pc =
   fall_through_pc - insn_size` so the BB is structurally a
   self-loop.
3. Both the parent BB template and the sub-template appear in the
   templates section; their ``template_id``\ s are independent and
   delta-encoded as usual in the body stream.
4. **Destination registers ride the LAST iteration, and only it.**
   Iterations 1..N-1 publish no destination-register write for the
   fanned-out instruction; iteration N publishes the instruction's whole
   architectural result.  Source registers are unaffected — every
   iteration reads its pointers and counter, so all N entries carry
   their sources.

   This is a property of the wire, not a capture limitation, and a
   consumer must read it as one: the absence of a register write on
   iterations 1..N-1 means *the instruction has not produced its result
   yet*, not *the value was not captured*.  A repeating instruction
   updates its architectural registers once, when it completes.  The
   fan-out exists so that the memops — which genuinely differ per
   iteration — have somewhere to attach; the registers do not differ per
   iteration in any sense a consumer may observe.

   Publishing intermediate per-iteration values would misrepresent the
   hardware in two ways that matter to anyone modelling a register file:
   it would imply a rename allocation per iteration, which no machine
   performs for a string or memory-copy instruction, and it would create
   a serial dependency chain of length N through the counter and pointer
   registers — turning a block copy that real hardware pipelines at many
   bytes per cycle into N dependent steps.  Under this contract the N
   entries are mutually independent: they all read the pre-completion
   pointer and counter values, and one of them writes the result.

   The value published on iteration N is the state the capture observed
   after the instruction completed, published at the entry where it
   becomes architecturally true.  It is not placed on iteration 1: that
   would republish a later instant's state at an earlier one.

   The rule is ISA-neutral and holds under every translation regime.
   x86 ``REP`` string operations and AArch64 ``FEAT_MOPS``
   (``CPYF*``/``SET*``) fan out through the same path and obey it, and a
   single-iteration translation (``-icount``), which *could* read each
   iteration's registers live, publishes the same single write in the
   same place.

What one iteration *is* differs by family, because only one of the two
has an architectural iteration to count.

For an x86 REP the loop is architectural — the count register
decrements once per element — so an iteration is one element, and each
entry's dyn_params carry that element's memops:

   - MOVS  → 1 load + 1 store
   - CMPS  → 2 loads
   - STOS  → 1 store
   - LODS  → 1 load
   - SCAS  → 1 load
   - INS   → 1 store (port → memory)
   - OUTS  → 1 load (memory → port)

A FEAT_MOPS instruction has no architectural iteration at all: it is
one instruction that moves an arbitrary span, and how that span is
divided into accesses is a property of the machine rather than of the
program.  The fan-out unit is therefore **one memory access** — each
body entry carries exactly one load or one store.  A copy consequently
alternates load-carrying and store-carrying entries in the order the
accesses occurred, rather than pairing them; that is the order the
transfer ran in, and the only one the wire asserts.  Read the iteration
count of a MOPS self-loop as a count of memory accesses, not of
architectural instructions: a single ``CPYM`` covering a megabyte
appears as roughly 65,000 entries.

How the span divides into accesses is nevertheless **stable**: the
reported decomposition is the transfer's page-bounded chunking into
naturally aligned power-of-two pieces of at most 16 bytes, greedy from
each chunk's base, whatever mechanism the emulation happened to move
the bytes with.  A watchpoint on the page, the first touch of a clean
page, wrong-path speculation, and an interrupt or fault splitting the
instruction mid-transfer never change the pieces: a page-aligned 4 KiB
``SETM`` span is 256 sixteen-byte stores under every one of them, and
the entries emitted before and after a split concatenate to the
unsplit sequence.  The single exception is device (MMIO) memory,
where the per-byte accesses are architecturally real — the device
observes each one — so they are reported as they happen, per byte.
For a copy, one page-bounded chunk's load run is reported before its
store run; a device-memory operand's per-byte reports instead
interleave at the point they occur.

The access count is anchored in architectural state: the SET/CPY
helpers publish each execution's byte progress from the size
register's own decrement (``qemu_plugin_rep_bytes``), and the sizes
of the delivered accesses must sum to it.  The writer verifies this
on every cleanly completed bulk op whose accesses it was asked to
capture, and reports the outcome in ``<outfile>.stats.log``:
``MOPS bytes checked`` for the ops it summed and matched, ``MOPS
bytes mismatch`` (which must read 0) for a sum that disagreed with
the register, and ``MOPS bytes unchecked`` for ops it could not sum
at all.

The third row is not a rounding term.  The anchor sums the DELIVERED
accesses, so it needs their sizes, and without ``memdata=1`` there
are none to sum: every bulk op then lands in ``unchecked``.  Measured
on a FEAT_MOPS probe, 14 ops read checked=14 / mismatch=0 /
unchecked=0 with ``memdata=1`` and checked=0 / mismatch=0 /
unchecked=14 without it.  A trace taken without memory data therefore
carries no byte-anchor evidence, and says so in its own stats rather
than reporting a verification it did not perform.

An execution that faults before moving anything — the first store of
a ``SET`` landing on a not-yet-mapped destination page — contributes
no entry: the instruction re-executes after the fault, and that
re-execution carries the instruction's single rendering.  A demand
fault therefore does not add an instruction to the trace, exactly as
an x86 REP's trailing pass does not.

An execution that moves nothing still executed the instruction and
still emits exactly one entry, carrying zero memops.  That is routine
rather than exceptional: ``memset(d, c, 0)`` does it, and so does every
transfer small enough for the prologue form to finish on its own,
leaving the main and epilogue forms with nothing to move.

Iterations are never aggregated onto a single entry with
``N_LOADS = N``.  That is what keeps these instructions — the only
unbounded memop issuers in the supported ISAs — within
``CST_FID_SLOT_COUNT`` however much memory they move.

For an x86 REP the iteration count on the wire is the instruction's own
count-register decrement, read from QEMU through
``qemu_plugin_rep_iterations`` — never a count of delivered memory-op
callbacks, which varies with how QEMU translated the instruction
(``-icount``, single-step, ``EFLAGS.TF``, the interrupt shadow, a
mid-REP exception).  The trailing re-entry a single-iteration
translation makes after the final iteration contributes no entry.  A
REP therefore renders the same entries, edges, memops and
destination-register writes under every translation, and on the wrong
path — always single-stepped — as on the correct path.  The register
half of that invariance is the rule above: exactly one destination
write, on the final iteration, whatever the translation.  A zero-count REP is a retired instruction and emits its
one entry, carrying no memops.

A demand fault inside an iteration does not change the entry count
either: the faulted iteration's entry renders the aborted attempt's
delivered accesses followed by the re-executed iteration's own, and
every other iteration renders exactly its architectural accesses.  This
holds per fault — a REP whose destination crosses several never-touched
pages faults once per page, and each faulting iteration carries its own
aborted attempt, at its own position in the iteration sequence.

The window clock does NOT follow the fan-out: a window budget counts
instructions in bbv-billed units — the per-TB-execution count the BBV
plugin produces under QEMU's canonical translation, the regime SimPoint
offsets are clustered in.  That is one tick per architectural
instruction, plus one per REP_MAX chunk boundary for an x86 REP (a
counter-terminated N-iteration REP is ``1 + floor((N-2)/65536)`` ticks;
measured on the bbv plugin directly — its loop translation deliberately
re-enters at those deterministic boundaries and bbv bills each entry).
Re-entries that the canonical translation would not make never tick:
a single-iteration REP pass (``-icount``, single-step, ``EFLAGS.TF``)
off a chunk boundary withholds, and a FEAT_MOPS re-entry always
withholds — a MOPS execution the emulator suspends mid-transfer and
re-enters is the same instruction continuing, a timing artifact with no
canonical-translation counterpart.  The clock is therefore identical
under every translation AND aligned with bbv counts.  Because the
fan-out writes one entry per iteration, a trace may contain more
entries than the window budget asked for; that is by design (see header
field 2.13 for the bridge between the two positions).

The window CLOSE is atomic with respect to a fan-out instruction, in the
same sense the 2.13 warmup boundary is: a window never ends part-way
through one architectural instruction's iterations.  A REP whose count
exceeds ``REP_MAX`` runs as several chunk executions, and a budget that
runs out between two of those chunks does not stop the trace there — the
close waits for the instruction to retire, and the window overruns its
budget by the remainder of that one instruction.  So a REP on the wire
carries either all of its architectural iterations or none, and a reader
may take a rendered REP's iteration count as the guest's own count-
register delta without checking whether the window ended inside it.

Two boundaries of that guarantee are worth stating.  It is carried by the
correct path's architectural iteration count, so it covers the families
that publish one — on the wrong path the question does not arise, because
speculation single-steps and never chunks.  And it is the one licensed
way a user-mode window with an explicit stop exceeds its budget: outside
a fan-out instruction the close cuts the crossing entry's range and
bills exactly the budget, and the ``covered=`` figure on the finishing
line is settled to the published count (instructions the clock counted
that no emitted range claims are un-billed at the close), so
``clock_minus_wire`` reads zero there too.  The settle covers both
edges of the window: a mid-run open — a later SimPoint cluster, or any
explicit start the run reaches while executing — lands on a
translation-block boundary, and the crossing block whose dispatch
carried the
clock past the start is traced whole, keeping the wire aligned with the
BBV-style count that positioned the window; the head instructions it
dispatched below the start are published, so they are billed to the
segment as a named open-boundary credit and ``covered=`` reads the
budget exactly on every cluster of a schedule, not just the first.  On
the wire side of that
comparison the fan-out surplus — the entries the fan-out writes beyond
the one count each clock keeps for the instruction, including the parent
entry of a fault-cut rep-split piece whose bill the fault re-credited —
is a named per-segment term the finishing line folds in, so a segment
containing fan-out instructions reads zero exactly when the identity
``covered + surplus = wire`` holds.  The trace's own instruction
count remains the authority for what the window contains.

::

   current n_loads = state(template, insn, CST_FID_N_LOADS)
   current n_stores = state(template, insn, CST_FID_N_STORES)

   valid load slots  = 0 .. n_loads-1
   valid store slots = 0 .. n_stores-1

The scalar ``LOAD_ADDR[k]`` and ``STORE_ADDR[k]`` fields address slots
``k ∈ [0, CST_FID_SLOT_COUNT)`` directly.  If an address field is
absent for one of these valid slots, the value is unchanged from
that slot's current baseline.

If an instruction's dynamic ``n_loads`` or ``n_stores`` would exceed
``CST_FID_SLOT_COUNT = 512``, the writer is permitted to elide the
trailing memops past the cap and emit a warning to
``unknown_warnings.log`` identifying the PC, opcode, and dropped-memop
count.  Consumers see only the first ``CST_FID_SLOT_COUNT`` memops in
that case; the elision is observable as the dynamic count being
clamped to the cap.  The wire format reserves no overflow path —
there is no ``EXTRA_*`` raw-vector escape.

This clamp is a backstop and nothing more: no instruction the writer
currently emits can reach it.  Instructions divide cleanly into two
groups, and the ceiling is where the line between them falls.

Every instruction with a *bounded* fan-out uses slots, and all of them
fit with room to spare.  The widest is not a vector instruction but a
processor-state save: x86 ``XSAVE``/``XSAVEOPT``/``XRSTOR`` write or
read the whole extended state area in one instruction — 88 stores on a
Haswell-class guest, and roughly 320 8-byte stores for a full AVX-512
area of about 2.5 KiB.  The vector cases sit far below that: AVX-512
gather/scatter is at most 16 lanes, ARM SVE2 at VLEN ≤ 4096 is at most
64 element loads, and RISC-V V at LMUL × VLEN/SEW is at most 64.  The
512-slot ceiling is sized by the ~320 case.

The instructions whose fan-out is *unbounded* — bounded only by a
register value, so that no ceiling could be chosen — are not clamped at
all.  They are fanned out into a self-loop of one body entry per
iteration, which puts every memop on the wire whatever the register
held: x86 REP-prefixed string operations and the AArch64 FEAT_MOPS bulk
copy/set family.  Those two are the whole of that class across the
supported ISAs; see :ref:`bulk-memory self-loop BBs
<fanout-self-loop-bbs>`.

An instruction outside both groups — a future ISA extension with an
unbounded fan-out the writer does not yet fan out — is what the clamp
exists for, and the ``memop_overflow`` warning is how it announces
itself.

The ceiling is a *wire* quantity only.  Sizing structures by it is
not required and the writer does not do it: the per-template field
state and the per-entry memop slot tables are both sized by the
highest slot an instruction has actually been observed to use, so an
instruction with one load costs the same as it did at a 64-slot
ceiling.  Consumers should size the same way.

5.3 Memory Data
^^^^^^^^^^^^^^^

When ``CST_FLAG_MEM_DATA`` is set, the data fields carry the observed
load/store value.

::

   512-bit data value:

     little-endian unsigned scalar, up to 64 bytes

Memory data values use the scalar ``LOAD_DATA[k]`` / ``STORE_DATA[k]``
delta records, indexed identically to ``LOAD_ADDR[k]`` /
``STORE_ADDR[k]`` (one data slot per memop slot, for
``k ∈ [0, CST_FID_SLOT_COUNT)``).  There is no separate overflow
path; the slot ceiling and overflow handling described in §5.2
apply uniformly to addresses and data.

Narrow accesses are masked to their low accessed bytes before
emission as a scalar delta.  The QEMU plugin mem-value API delivers a
value directly only up to 128 bits; a wider single access is read back
out of guest memory instead, up to the format's 64-byte ceiling.  A
data slot is therefore OPTIONAL independently of its address slot: an
address and a size are recorded whether or not the value could be
obtained, and a consumer distinguishes "no value" from "a value of
zero" by the absence of the ``LOAD_DATA[k]`` / ``STORE_DATA[k]`` field,
never by its content.  See :ref:`memory-value width
<limits-mem-value-width>` for what the read-back does and does not
observe.

5.3.1 Physical Addresses (physaddr)
"""""""""""""""""""""""""""""""""""

When ``CST_FLAG_PHYSADDR`` is set (system-mode ``physaddr=1``), each memop slot
may carry a ``CST_FID_LOAD_PPAGE{k}`` / ``CST_FID_STORE_PPAGE{k}`` field giving
the **physical PAGE base** of the access — the physical address masked to
the 4 KiB page granule (``cst_wire::PPAGE_SHIFT``).  The consumer rebuilds
the full physical address by ORing the page base with the in-page offset,
which the virtual address already carries:

::

   paddr = ppage | (vaddr & PPAGE_OFFSET_MASK)          PPAGE_OFFSET_MASK = 0xFFF

The offset is not duplicated on the wire — it rides the existing
``LOAD_ADDR{k}`` / ``STORE_ADDR{k}`` virtual address.  A 4 KiB granule
reconstructs the **exact** physical address regardless of the guest's real
hardware page size: for any page ≥ 4 KiB the low 12 bits of a virtual
address equal the low 12 bits of its physical address, so the masked-off
offset is identical whether taken from the VA or the PA.  A larger hardware
page (16 KiB MIPS, 2 MiB / 1 GiB huge pages) merely re-emits the (unchanged)
page base once per 4 KiB step; correctness does not depend on the granule.

Only *lazily-observed* translations appear (see §5.1): the first access to a
page records its base, subsequent in-page accesses cost nothing, and an OS
remap self-corrects on the next touch.  An access with no observable
translation (MMIO, or a garbage-filled wrong-path access to an absent page)
emits no record, so the running per-``(template, ins_pos, slot)`` value simply
holds.  The consequence differs by path:

* **Correct path** — every CP access has a real RAM translation and a
  changed translation always emits a delta, so the reconstructed physical
  address is *exact* for every CP memop.
* **Wrong path** — a speculative access served synthetic data (see the
  ``CST_BB_FLAG_SYNTHETIC_FAULT`` machinery, §4.4) has no translation and emits
  nothing; the decoded value for that WP memop is then the slot's *last
  observed* translation — best-effort, and possibly stale for the wild
  address.  TLB-hit WP accesses carry their real translation exactly like
  CP ones.

MMIO device traffic is carried separately by the ``BODY_TAG_DEVIO_*``
records, not by ``PPAGE``.

5.4 Register Data
^^^^^^^^^^^^^^^^^

When ``CST_FLAG_REG_DATA`` is set, register fields carry post-execution
snapshots for the template's destination register slots only. Source
register identities remain in the template's ``src_regs`` array, but
source values are not emitted on the wire — destination values
strictly dominate (they cover every architectural write, so consumers
can derive any register's value at any point from the most recent
post-write observation, and there are typically fewer destinations
than sources per insn so the cost is lower).

::

   template instruction:

     src_regs = [ REG_A, REG_B, ... ]   static source identities only
     dst_regs = [ REG_C, ... ]

   delta fields for this instruction:

     CST_FID_DST_REG0  -> value of REG_C after execution

Capture timing: each per-insn destination snap is taken at the first
moment after the instruction's body completes — for non-tail insns
that's the pre-exec hook of the next canonical insn; for the tail
insn of every TB it's the next TB's tb_exec callback. Both points
guarantee the architectural register state reflects the just-finished
instruction's writes and not yet the next instruction's.

This timing is what the entry's ``bb_stop`` is measured against
(§4.2a).  An instruction whose successor point has not been reached is
not observable yet, so it lies outside the range and the entry carries
no snapshot for it; an instruction inside the range carries a snapshot
for every destination its template declares.  The rule holds
regardless of ``CST_FLAG_REG_DATA``: the flag decides whether the
captured values are written to the wire, never how far the range
extends, so a trace's block ranges are identical with register data on
and off.

Register snapshots are scalar 512-bit values. The capture path copies
up to the first 64 little-endian bytes returned by
``qemu_plugin_read_register()``.

Register IDs are one-byte ``GenericRegId`` values. The trace header's
``reg`` map gives the exact name for each value, including special values
such as ``REG_ZERO``.

Current generic register layout:

::

   +-------------+---------------------------+
   | Values      | Class                     |
   +-------------+---------------------------+
   | 0           | REG_NONE                  |
   | 1..32       | REG_GPR0..31              |
   | 33..48      | REG_CTRL0..15             |
   | 49..64      | REG_DEBUG0..15            |
   | 65..96      | REG_FPR0..31              |
   | 97..100     | REG_ACCHI0..3             |
   | 101..110    | privileged behaviour      |
   | 111..128    | unallocated               |
   | 129..192    | REG_VEC0..63              |
   | 193..224    | REG_PRED0..31             |
   | 225..230    | REG_SEG0..5               |
   | 231..249    | compressed special        |
   | 250..254    | common specials           |
   +-------------+---------------------------+

The general-purpose and floating-point banks are 32 wide because no
supported ISA numbers more than 32 of either file; the space that
leaves carries the x86 control and debug files, the accumulator high
halves and the privileged behaviour classes.  The vector and predicate
banks keep their full width, and their upper halves hold the
architecturally distinct registers that fall outside an ISA's numbered
file but belong to its behaviour class — AArch64 ``ZT0`` at
``REG_VEC32``, ``FFR`` at ``REG_PRED16``.

The privileged band 101..110 is ``REG_SYSEXC``, ``REG_SYSMMU``,
``REG_SYSTIMER``, ``REG_SYSPERF``, ``REG_SYSDBG``, ``REG_SYSCACHE``,
``REG_SYSID``, ``REG_COPROC0``, ``REG_COPROC1`` and ``REG_SYSFPEN``.
Which of them a system register lands on is decided at the decode
boundary and not by the ISA register table, on every ISA whose system
registers Capstone has no register id for: the operand carries an
architectural role in ``sysreg_class`` — ``QEMU_PLUGIN_SYSREG_IDENT``
for a read-only implementation constant, ``_EXC``, ``_MMU``,
``_TIMER``, ``_PERF``, ``_DBG``, ``_CACHE``, ``_FPENABLE`` for the
other behaviour groups, ``_FLAGS``, ``_FPCTRL``, ``_VECCTRL``,
``_THREADPTR``, ``_SHADOWSTK`` for the single-register classes, and
``_OTHER`` for the residual — and the plugin renames the role to the
ID.  The role does not travel on the wire; the ID does.
:doc:`reference` tabulates the whole mapping.
The
compressed-special band holds the classes that are one register rather
than a bank: ``REG_BOUND0..3``, ``REG_ACC0..3``, ``REG_ZERO``,
``REG_MATRIX``, ``REG_SYS``, ``REG_FCSR``, ``REG_VCTRL``, ``REG_TLS``
and ``REG_SSP``.

Two registers that a renaming regfile would not have to order against
each other never share an ID.  System and control registers are spread
across the classes above rather than folded onto ``REG_SYS`` because
an edge onto a register the instruction never touched misleads a
consumer as badly as a missing one — a thread-pointer read must not be
ordered behind an unrelated ``mrs``, and a read of a read-only
identification register must not be ordered behind anything at all.
The converse also holds: two ISA names for the same hardware register
share one ID, which is why AArch64 ``v0``/``z0``, x86
``xmm16``/``ymm16``/``zmm16`` and the register-list and LMUL-group
spellings resolve to the registers they denote.  :doc:`reference`
carries the per-ID notes.

The header map, not this table, is authoritative for decoding names.

5.5 Instruction Metadata
^^^^^^^^^^^^^^^^^^^^^^^^

Instruction metadata fields default to the template instruction. They
are emitted only when the current execution differs from the current
baseline.

::

   template instruction bytes/opcode/branch/immediate
             |
             v
   first execution uses template defaults
             |
             v
   INSN_* sparse records update only changed fields

This permits traces where an instruction's raw bytes or classification
changes without forcing a new template record.

5.6 Branch Outcome
^^^^^^^^^^^^^^^^^^

Two singleton field-IDs make a branch-terminated block's control-flow
outcome explicit, so a consumer never has to decode the successor to
recover it:

* ``CST_FID_BRANCH_TAKEN`` — ``1`` when the terminating branch transferred
  control, ``0`` when it fell through.
* ``CST_FID_BRANCH_TARGET`` — the branch's landing PC encoded as a
  **signed displacement** from the branch instruction's own PC
  (``successor − branch_pc``), *not* the raw PC.  A consumer reconstructs the
  absolute successor as ``branch_pc + displacement``, where ``branch_pc`` is the
  template PC of the terminating branch insn.  When not taken this resolves
  to the template's ``fall_through_pc``, so ``BRANCH_TARGET`` is the
  architectural successor in both directions.

Both ride the ``ins_pos`` of the BB's terminating branch — the
highest-indexed branch-type instruction (``n-1`` normally, ``n-2`` on a
delay-slot tail, matching the writer's ``template_branch_index``) — and are
delta-encoded against that instruction's own previous value with baseline
default ``0``, exactly like ``METAFLAGS``.  Encoding the target as a
displacement keeps even a first sighting a small sleb: a **static direct
branch** costs a tiny displacement record once (plus, if taken, its
direction) and **zero bytes** on every later execution; a **conditional**
branch pays a one-byte direction delta only when its outcome flips; an
**indirect** branch pays a (still-compact) displacement delta whenever the
target moves.  A consumer reconstructs the direction it would otherwise
derive by look-ahead as ``taken == (target != fall_through_pc)``, with an
unconditional terminator always taken — identical to the writer's
classification.

Coverage and gating:

* **Correct path and wrong path.**  The two FIDs ride a branch-terminated
  block on the correct path *and* on every wrong-path (WP) chain block.  A WP
  block's successor is the walker's landing PC (the next chain block's
  ``start_pc``, or, for the chain's last block, where the excursion would have
  continued).  On WP the singletons delta through the same per-chain WP
  field-state overlay as ``LOAD_ADDR`` — ``wp_state → CP state → default`` — so a
  WP branch repeating a correct-path or earlier-WP displacement costs zero
  record bytes, and WP branch overhead tracks CP branch overhead rather than
  paying a fresh baseline per excursion.
* **Always advertised**, not header-gated: a post-branch writer names both
  in every trace's ``field_id`` map (they cost nothing on non-branch entries).
  A trace produced by a writer that predates the feature names neither, and
  a consumer then falls back to successor look-ahead.
* **Only where the range reaches the branch.**  Two populations carry
  neither FID and have no outcome to surface.  A template with no
  terminating branch at all — a page-split continuation — is the
  first.  The second is any entry whose executed range (§4.2a) stops
  at or before the terminating branch's ``ins_pos``: that entry did
  not run the branch, so it has no direction and no target, and a
  decoder MUST NOT read the two cells for it.  This is routine rather
  than rare — every interrupted block contributes one such entry — so
  a consumer treats "no outcome on this entry" as an ordinary state,
  and looks for the invocation's outcome on the entry whose range does
  contain the branch.

  .. warning::

     The range rule above is what makes an absent outcome *readable* as
     absent, and it is load-bearing.  The two FIDs delta-persist per
     ``(ins_pos, fid)``, so an entry that carries neither record reads back
     as a repeat of whatever last occupied that slot — for ``BRANCH_TAKEN``
     that can be a different template's branch at the same index.  Omission
     alone therefore does not mean "no outcome"; it means "unchanged".  A
     consumer must decide by the range — an entry whose ``bb_stop`` does not
     pass the terminating branch has no outcome, whatever the cells hold —
     and never by whether records were present.
     A block whose range *does* contain the branch, but whose successor the
     writer could not resolve, is the third population, and it is named
     explicitly: the writer MUST NOT publish an unresolved outcome as if
     observed.  It stages neither FID and sets
     ``CST_BB_FLAG_BRANCH_UNRESOLVED`` on that entry's block record
     (§5.7) — absence of the two records plus the flag *is* the wire's
     "unresolved".  A consumer reads such an entry's branch cells as
     stale by construction and takes no outcome from them; the flag,
     like every block flag, delta-persists and is re-cleared by the
     writer on the template's next resolved execution.
* **REP string operations** fan out into one entry per iteration, all at the
  REP PC; the self-looping REP "branch" is reported taken to its own PC for
  every iteration but the last, which exits to the real successor — so the
  per-entry outcome tracks the emitted successor sequence exactly.

**Successor adjacency and diversion.**  ``BRANCH_TARGET`` is the
**architectural** successor: the PC the branch sent control to.  It is not a
promise about the next record.  On a user-mode trace the two coincide — the
next entry of the same ``(thread_id, asid)`` context starts at the target,
which is exactly the look-ahead the FIDs spare a consumer.  A system-mode
trace also carries the OS, and there the next entry in a context need not be
where the branch went:

* **An excursion intervenes.**  A synchronous fault, a syscall or (with
  ``interrupts=1``) an asynchronous interrupt diverts to handler code, whose
  blocks are emitted before the target's first instruction retires.  The
  handler's entry carries a higher ``fault_depth`` (§4.2a).
* **The target's block faults part-way.**  A faulting block is emitted
  as the ranges it ran (§4.2a), in program order, with the handler's
  blocks between them.  The branch that entered it names its
  ``start_pc``, which is the first entry's own resume PC; each
  excursion's return names the next entry's, ``insn_pcs[bb_start]``.
  The record that follows either of them is the handler, not the
  block's continuation.
* **Strands interleave.**  Kernel work owned by one traced context but
  executed on several vCPUs is stamped with that one context, so consecutive
  entries can belong to independent strands.
* **Blocks are gated out.**  A foreign address space or a guest-thread
  handoff can keep the target's own blocks out of the trace entirely, so the
  branch's target is never reached again in that context.

In every one of those cases the encoded target is right and the adjacent
record is not the continuation.  A consumer that reconstructs control flow
from ``BRANCH_TARGET`` is unaffected — that is what the FIDs are for.  A
consumer that instead *derives* the outcome by look-ahead is wrong wherever
the OS intervenes.

``cst_decode --verify-branch`` therefore cross-checks both singletons against
the architectural continuation rather than against adjacency: direction
against the encoded target itself (``taken == (target != fall_through_pc)``,
unconditional terminators forced taken), and the target against the entry
where the context resumes the target's instruction stream.  Every entry has
exactly one resume PC — ``insn_pcs[bb_start]``, which is ``start_pc`` on an
entry that began the block — so the match is an equality against one PC
rather than a membership test against a set of alternatives.  A pair whose
adjacent record does not carry the target is deferred only when the trace
positively signals the diversion (a ``fault_depth`` step, a successor entry
whose ``bb_start`` is non-zero, a thread switch, a privilege-domain gap, or
both endpoints inside a kernel excursion), and the deferred target must then
be matched by a later entry of the same context — directly, at that entry's
own resume PC (*resumed*), or indirectly, at a later block of the excursion
naming the same PC (*corroborated*).  Every deferral is tallied by signal
with its resumed / corroborated / never-resumed split, so a suppression
cannot hide inside the diversion accounting.  A resumed entry is checked from
the other side as well: its resume PC must be the encoded target of some
branch in that context.  Non-final WP
blocks are cross-checked in-chain against the next chain block's
``start_pc``; a block whose ``CST_FID_BB_FLAGS`` marks it faulting or
untranslatable ends its strand and is tallied as a diversion.  A
syscall-class block is exempt from that licence and checked strictly: the
wrong path continues past a syscall at its architectural fall-through, so
its successor is exactly predictable, and the fault marker it always
carries (raising is how a syscall leaves speculative execution) does not
excuse a mismatch.

5.7 Block-Level Fields (BLOCK_POS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some facts belong to the basic-block execution rather than to any one
of its instructions: how much of the block ran, at what exception
depth, and what happened to it.  They are carried by field-delta
records exactly like per-instruction facts, addressed at the reserved
position ``BLOCK_POS = template.num_insns`` (§5), inside the same
``cp_delta_section`` / ``wp_delta_section`` the block's instruction
records ride.  There is no separate section, no count, and no framing
of their own: a block with nothing to declare emits no record and pays
no bytes, and a block with something to declare pays one record for
it.

**The position is the referenced template's own.**  ``BLOCK_POS`` is
not a constant of the format; it is ``num_insns`` *of the template the
section's owning record names*, so two templates of different lengths
place their block cells at different positions, and the same numeric
``ipos`` that is an instruction of one template is the block of
another.  A reader therefore resolves ``BLOCK_POS`` per section, from
the ``template_id`` actually referenced — the same rule that already
governs every per-block structure, because revisions at one
``start_pc`` need not agree in ``num_insns`` (Step 0, §6).  Sizing the
position from any other template — a sibling revision, a hard-coded
length, the previous entry's template — misreads a block record as an
instruction record or the reverse.

**The dispatch is closed.**  Within a section whose template has ``N``
instructions, a record's position decides what it addresses, and the
decision has exactly three outcomes: ``ipos < N`` addresses
instruction ``ipos``; ``ipos == N`` addresses the block; ``ipos > N``
is malformed, and a reader MUST reject the trace rather than skip the
record — skipping is the licence for *unrecognised field names*
(Forward compatibility), never for impossible positions, of which this
epoch defines none above ``BLOCK_POS``.  A decoder built as a loop
"over the instructions" must route ``ipos == N`` to the block rather
than treat it as an out-of-range instruction index: ``BLOCK_POS`` is a
position of the *section*, one past the end of the instruction array
it also spans.

**Names belong to positions.**  The five ``CST_FID_BB_*`` names in the
table below are the complete block-level family of this epoch, and
they are valid *only* at ``BLOCK_POS``.  Every other field family —
the slotted memop and register families, ``N_LOADS`` / ``N_STORES``,
``METAFLAGS``, the lane masks, the widths, the ``INSN_*`` metadata
singletons, and the branch-outcome singletons — is per-instruction and
valid *only* at instruction positions.  A recognised name found at the
wrong kind of position is malformed and rejected (Step 6.9); an
unrecognised name is consumed and skipped at either kind, which is how
future observations — block-level as much as per-instruction — are
added without a new epoch.  Note that membership follows the field's
*family*, not the scope of the fact it states:
``CST_FID_BRANCH_TAKEN`` / ``CST_FID_BRANCH_TARGET`` describe how the
block exited, but they are per-instruction fields riding the
terminating branch's own ``ins_pos`` (§5.6), and their appearance at
``BLOCK_POS`` is exactly as malformed as a load address there.

Every rule of §5 applies unchanged.  State is keyed
``(template_id, BLOCK_POS, field_id)``: a template's field-state table
has ``num_insns + 1`` positions, and the last row is the block's.  The
row **persists across entries** for the whole body stream exactly like
the instruction rows, so a value repeated by the next execution of the
same template costs zero bytes.  CP and WP keep separate overlays with
the block row present in both: a CP record writes the CP overlay, a WP
record writes the WP overlay and resolves its baseline
``WP → CP → template default``, so a speculative block whose range or
flags match the correct path's costs nothing to say so.  IFRAMEs
encode block-level records against fresh overlays like every other
field, making them absolute — the ``BLOCK_POS`` row is part of what an
IFRAME reproduces (§4.5).

Because state persists, **omission means "unchanged", never
"absent"**.  A writer MUST emit a record whenever a block's value for
one of these fields differs from that cell's current value — including
the return to a default, such as a template that ran partially once
and runs whole thereafter, or a wrong-path block that reported a
synthetic fault last time and does not this time.  The duty is
absolute because the failure is invisible: a cell the writer lets
stick misreports every later execution of that template, and a reader
has no way to tell a stuck value from a genuine repeat.

**The whole section defines the entry.**  Records arrive in
non-descending ``(ipos, fid)`` order (§5), and ``BLOCK_POS`` is the
highest position a section has, so a block's records are always the
section's last — the executed range arrives *after* the
per-instruction records it scopes.  A consumer therefore MUST apply
every record of a delta section before interpreting the entry: what a
per-instruction record means — whether its position was executed at
all — is not knowable until the section's tail has been read.  This
costs nothing beyond the two-pass shape the delta model already
requires (apply deltas, then materialise).

**The range scopes instruction records.**  A writer emits
per-instruction records only at positions inside the entry's declared
``[bb_start, bb_stop)`` (§4.2a); the block's own records at
``BLOCK_POS`` sit outside every instruction range by construction and
are always legal.  A per-instruction record at an in-template position
*outside* the declared range is malformed, and a reader MUST reject
the trace.  Because the range rides the section's tail (records are
ordered by position and ``BLOCK_POS`` is the highest), the check runs
once the section has been parsed — the same two-pass shape the delta
model already requires (apply deltas, then materialise) — with each
record's position tested against the range the section's own block
records resolve to.  A rejected trace's cell updates are moot; no
overlay state escapes a rejection.

::

   block-level field-IDs, all addressed at ipos == BLOCK_POS

   +-------------------------------+---------+---------------------+
   | field_id                      | default | scope               |
   +-------------------------------+---------+---------------------+
   | CST_FID_BB_START              | 0       | CP and WP blocks    |
   | CST_FID_BB_STOP               | num_insns | CP and WP blocks  |
   | CST_FID_BB_FLAGS              | 0       | CP and WP blocks    |
   | CST_FID_BB_FAULT_DEPTH        | 0       | CP blocks           |
   | CST_FID_BB_FAULT_INSN         | 0       | WP blocks           |
   +-------------------------------+---------+---------------------+

``CST_FID_BB_START`` / ``CST_FID_BB_STOP`` are the executed range
``[bb_start, bb_stop)``, in template instruction indices, ``bb_stop``
exclusive.  ``CST_FID_BB_STOP``'s baseline default is the block's own
``num_insns`` — the only per-template baseline outside the
instruction-metadata family — so the whole-block case is the free one:
an entry that ran its block from the first instruction to the last
carries neither record.  §4.2a states what a declared range means for
the entry's contents; the normative summary is that memops and
register snapshots exist for the instructions inside the range and for
no others, and that a consumer clamps every per-instruction walk to
it.  A reader MUST reject an entry whose decoded range does not
satisfy ``0 <= bb_start < bb_stop <= num_insns``.

``CST_FID_BB_FLAGS`` is a bitmask whose bits resolve through the
``bb_flag`` map (§2).  Bits a reader does not recognise are ignored,
per the reserved-bits rule; the map states which bits this trace can
set.

``CST_FID_BB_FAULT_DEPTH`` is the exception-nesting depth described in
§4.2a.  It is a per-template cell like any other, so a block that only
ever runs at one depth pays one record at its first sighting and
nothing afterwards, and a block that runs at two pays only on the
change.

``CST_FID_BB_FAULT_INSN`` is the instruction index of a wrong-path
block's synthetic-data fault, meaningful only when the same block's
``CST_FID_BB_FLAGS`` carries ``CST_BB_FLAG_SYNTHETIC_FAULT``.  It is
deliberately not ``bb_stop``: the excursion continues past it (§4.4).

Wrong-path blocks use the identical convention.  Each chain block's
``wp_delta_section`` (Step 6.8) carries that block's own block-level
records at *its own* ``BLOCK_POS`` — resolved from the chain block's
``wp_template_id``, not the CP entry's — through the WP overlay's
block row.  This is how a speculative block's partial execution
reaches the wire at all: its range rides ``CST_FID_BB_START`` /
``CST_FID_BB_STOP`` exactly as a correct-path block's does (§4.3), and
its events ride ``CST_FID_BB_FLAGS`` / ``CST_FID_BB_FAULT_INSN``
(§4.4).

Two positions, one dictionary.  A decoder needs no second state table,
no second record shape and no second pass — the block's cells sit in
the last of the ``num_insns + 1`` rows of the table it already keeps,
one index past the block's instructions, and the only new obligations
are to apply the whole section before it materialises anything and to
clamp what it materialises to the declared range.

Worked example: four emissions of one template
""""""""""""""""""""""""""""""""""""""""""""""

The bytes below follow §4.2a's running example — template ``T`` with
``num_insns = 7``, so ``BLOCK_POS = 7`` — through four consecutive
correct-path emissions: a run interrupted by a fault at instruction 3,
its continuation, and two whole runs.  The template is warm (every
cell shown has a prior observation), and instruction 1 performs one
load whose address moved by 8 bytes before entry A and then holds
still.  This trace's
``field_id`` map assigns ``CST_FID_LOAD_ADDR0 = 8``,
``CST_FID_BB_START = 300`` and ``CST_FID_BB_STOP = 301`` — illustrative
values; a reader resolves the names through the map, never through
these numbers.

Entry A — the run before the fault, ``[0, 3)``.  One instruction
record, then one block record:

::

   08                len = 8 (section framing, Step 6.4)
   02                n_records = 2
   01 08 08          ipos_delta=1 → ipos 1 (< 7: instruction record)
                     fid  = 8      CST_FID_LOAD_ADDR0
                     delta = SLEB(+8): the load moved 8 bytes
   06 AD 02 7C       ipos_delta=6 → ipos 7 (== 7: BLOCK record)
                     fid  = AD 02  ULEB(301) = CST_FID_BB_STOP
                     delta = SLEB(-4): cell 7 (default) → 3

   cells after:  bb_start = 0 (default, no record)   bb_stop = 3
   declared range [0, 3)

The interruption itself costs nothing further: no flag, no depth
record — the shortened range *is* the statement.  ``BB_START`` needs
no record because the run began at 0, the cell's value already.  The
handler's blocks follow as ordinary entries of their own templates
(each carrying its own ``CST_FID_BB_FAULT_DEPTH`` record at its own
``BLOCK_POS`` when its depth first differs from its cell).

Entry B — the continuation, ``[3, 7)``.  Nothing changed for
instructions 3..6 (their cells all repeat), so the section is two
block records and nothing else:

::

   09                len = 9
   02                n_records = 2
   07 AC 02 03       ipos_delta=7 → ipos 7 (BLOCK record)
                     fid  = AC 02  ULEB(300) = CST_FID_BB_START
                     delta = SLEB(+3): cell 0 → 3
   00 AD 02 04       ipos_delta=0 → still ipos 7; fid 301 ≥ 300
                     keeps the (ipos, fid) sort non-descending
                     fid  = AD 02  ULEB(301) = CST_FID_BB_STOP
                     delta = SLEB(+4): cell 3 → 7

   cells after:  bb_start = 3   bb_stop = 7
   declared range [3, 7)

``BB_STOP``'s delta is ``+4``, not ``0``: the baseline is the *cell*
(3, persisted from entry A), not the template default (7).  Entry B
carries no record for the instruction-1 load — position 1 is outside
``[3, 7)``, and an entry never emits observations outside its range
(§4.2a).

Entry C — the next invocation runs whole, ``[0, 7)``.  Returning to a
default is a change like any other, but only for the cell that moved:

::

   05                len = 5
   01                n_records = 1
   07 AC 02 7D       ipos_delta=7 → ipos 7 (BLOCK record)
                     fid  = AC 02  CST_FID_BB_START
                     delta = SLEB(-3): cell 3 → 0

   cells after:  bb_start = 0   bb_stop = 7
   declared range [0, 7)

``BB_STOP`` emits nothing — its cell already reads 7, which is this
run's value.  Omitting the ``BB_START`` record instead would be the
stuck-cell writer defect described above: the entry would decode as
``[3, 7)``, a partial run that never happened.

Entry D — another whole run, and this time nothing anywhere changed
(the load repeated its held address, every cell reads this run's
value).  The whole-block execution emits zero block records — and
here, zero records at all:

::

   01                len = 1
   00                n_records = 0

   cells after:  bb_start = 0   bb_stop = 7   (both untouched)
   declared range [0, 7)

This is the empty case the design prices at nothing: a block with
nothing to declare pays one byte of section framing, exactly what it
paid before block-level fields existed.  In all four entries the range
was read *after* the whole section was applied — in entry A the
per-instruction record preceded the ``BB_STOP`` record that scoped it,
which is the normal order, block records being always last.

6. Templates Section
~~~~~~~~~~~~~~~~~~~~

The templates section is mandatory and is appended at the tail of the
header member, immediately after the encoding maps section.
``template_id`` is the sole identity of a template; ``start_pc`` is
**not** unique.  A self-modified block emits multiple templates that
share a ``start_pc`` but differ in ``template_id`` and instruction
bytes — its revision history, minted lazily on re-execution of
mutated bytes (Step 0).  Revisions at one ``start_pc`` need not agree
in ``num_insns`` or in their per-instruction PCs and sizes: a guest
that re-cuts a block into different instructions mints a revision of
the new shape, and the wire carries it exactly as it carries any other
template.  A block the guest entered and did not finish mints nothing:
the entry names the whole block and declares the range that ran
(§4.2a), so a shorter execution is a body fact, not a template.  The
one non-self-modifying way two templates come to share a ``start_pc``
is a block whose continuation was never translated, which leaves what
was translated as a template of its own.  A body ``ENTRY`` (§4.2)
always names a block
by ``template_id``; never resolve a block by ``start_pc`` alone, and
never size a block from a sibling revision.

::

   templates section:

     num_templates : ULEB

     repeat num_templates times:
       tmpl_len   : ULEB
       tmpl_bytes : bytes[tmpl_len]

Each template payload is buffered so its byte length can be written
before the payload.

::

   template payload:

   +--------------------------------------------------+
   | template_id      ULEB                            |
   | start_pc         ULEB                            |
   | num_insns        ULEB                            |
   | fall_through_pc  ULEB    not-taken edge          |
   | n_targets        ULEB    0/1/k (see Step 4.3)    |
   |   target_pc      ULEB  x n_targets  taken edges  |
   | symbol_name      string                          |
   +--------------------------------------------------+
   | repeated num_insns times:                        |
   |   pc_delta        ULEB    pc - previous_pc       |
   |   opcode          u8      GenericOpcode          |
   |   branch_type     u8      BranchType             |
   |   flags           u8      CST_INSN_FLAG_* bits   |
   |   n_src           u8                             |
   |   n_dst           u8                             |
   |   src_regs        u8[n_src]                      |
   |   dst_regs        u8[n_dst]                      |
   |   max_dep_loads   u8      template-static MAX     |
   |   max_dep_stores  u8      template-static MAX     |
   |   immediate       SLEB    only if HAS_IMM        |
   |   insn_size       u8                             |
   |   insn_bytes      bytes[insn_size]               |
   |   dep_block               only if HAS_DEP_BLOCK  |
   +--------------------------------------------------+

When ``flags & CST_INSN_FLAG_HAS_DEP_BLOCK``, an extensible dependency
sub-block follows the instruction bytes:

::

   dep_block:
     dep_block_flags   u8        CST_DEP_BLOCK_HAS_REG | CST_DEP_BLOCK_HAS_ADDR
     if HAS_REG:
       dst_dep[d]            ULEB    for d in 0..n_dst-1
       store_data_dep[s]     ULEB    for s in 0..max_dep_stores-1
     if HAS_ADDR:
       load_addr_dep[l]      ULEB    for l in 0..max_dep_loads-1
       store_addr_dep[s]     ULEB    for s in 0..max_dep_stores-1

Mask array sizes (``n_dst``, ``max_dep_loads``, ``max_dep_stores``) all
come from the outer template header — the dep block itself carries
only the masks.  ``max_dep_loads`` / ``max_dep_stores`` are the
template-static MAX counts; the runtime per-iteration mem-op counts
ride on ``CST_FID_N_LOADS`` / ``CST_FID_N_STORES`` and can be smaller
(e.g. a conditional load that didn't fire) but never larger.

Bit layout inside each register/load mask:

::

   bits [0, n_src)                            depends on src_reg[i]
   bits [n_src, n_src + max_dep_loads)        depends on load_data[i - n_src]
   bit  n_src + max_dep_loads                 depends on the immediate

Address masks omit the load-data bits because addresses are computed
before any load fires:

::

   bits [0, n_src)                            depends on src_reg[i]
   bit  n_src                                 depends on the immediate

An address mask names every register the effective address reads: the
base and index registers, and — on x86 with a segment override — the
segment register whose base is added in (``mov %fs:0x28, %rax`` reads
``fs``, so ``REG_SEG3`` is among that memop's address inputs, and among
the instruction's ``src_reg`` entries).  Segment registers appear only
in this role; no other ISA has segmented addressing.

Absence of ``CST_INSN_FLAG_HAS_DEP_BLOCK`` is the implicit all-to-all
over-approximation: every dst / store depends on every src / load.
Consumers that don't model intra-instruction dataflow can ignore
the block.

Vector lane masks
^^^^^^^^^^^^^^^^^

When ``CST_INSN_FLAG_VEC`` is set the writer emits the four
lane-mask field families (Reference §5.1).  They are **per
operand**, not a single replicated value, and **dynamic** —
delta-encoded like every other slotted field, so they cost bytes
only when they change:

* ``SRC_LANE_MASK{k}`` / ``DST_LANE_MASK{k}`` — which lanes of source
  slot ``k`` / destination slot ``k`` participate this execution.  The
  src and dst masks are independent (an element insert writes one
  dst lane while reading the rest as pass-through).
* ``LOAD_DATA_LANE_MASK{k}`` / ``STORE_DATA_LANE_MASK{k}`` — which lanes
  take their value from / are drained by memop slot ``k``.  These are
  computed at run time from the memop's address and size relative to
  the access base and the vector element width, so a structure load
  that fans into several lanes via several memops, or an
  immediate-selected single-element insert/extract, produces the
  correct per-memop lane partition.

The active-lane count can be fixed by the instruction encoding
(x86/NEON/MSA — derivable statically) or read from a register at
execution time (RISC-V V ``vl``; future x86 EVEX k-mask / AArch64 SVE
predicate).  This distinction is **writer-internal**: it only
decides where the writer reads the live-lane value from.  On the
wire there is no "static vs dynamic" kind — every family is just a
dynamic delta-encoded mask, and a consumer treats them uniformly.
A trace without ``CST_INSN_FLAG_VEC`` (scalar insns) carries no lane
masks; consumers then treat every lane as participating.

``CST_INSN_FLAG_LANE_PARALLEL`` records that lane ``j`` of each dst
depends only on lane ``j`` of every src (true SIMD lanes); when clear
the lanes still participate but cross-couple (shuffles, broadcasts,
horizontal reductions).

Lane-granularity dependency resolution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The dep block above is **coarse** — when an instruction has no
precise refiner its ``dst_dep`` / ``store_data_dep`` masks are the
all-to-all over-approximation.  A consumer recovers the precise
*per-lane* dependency by intersecting the coarse dep masks with the
per-operand lane masks and the address masks, all of which are on
the wire:

1. An input listed in ``dst_dep[d]`` that is a vector operand feeds
   destination ``d`` only on the lanes where its ``SRC_LANE_MASK`` (or
   ``LOAD_DATA_LANE_MASK``) intersects ``DST_LANE_MASK[d]``.  Zero
   intersection ⇒ that input does not feed that destination at all.
2. A src that appears only in a ``load_addr_dep`` / ``store_addr_dep``
   mask feeds the destination only transitively through the memop
   (the destination depends on the load; the load address depends
   on that src) — it is not a direct data dependency.

Worked example — ``pinsrd $3, 0xc(%rsp), %xmm0`` (insert one dword
from memory into lane 3 of xmm0):

* ``DST_LANE_MASK`` for xmm0 = ``{3}``; ``SRC_LANE_MASK`` for the
  pass-through read of xmm0 = ``{0,1,2}``; ``LOAD_DATA_LANE_MASK`` for
  the load = ``{3}``.
* Coarse ``dst_dep`` is all-to-all (rsp, xmm0, load, imm).
* Resolved: lane 3 of xmm0 depends only on the load (``{3}∩{3}``);
  the pass-through xmm0 read (``{0,1,2}∩{3}=∅``) does **not** feed
  lane 3; rsp feeds the load address only (shown via
  ``load_addr_dep``), so xmm0 lane 3 ← load, load addr ← rsp.

The ``cst_decode --show-lanes`` / ``--show-deps`` renderer implements
exactly this reconstruction and is the reference for it.

``pc_delta`` is relative to the previous instruction PC, with
``previous_pc = start_pc`` for the first instruction. The branch, if any,
is the last instruction after the writer's delay-slot normalization.

Template profile block
^^^^^^^^^^^^^^^^^^^^^^

Appended to every template payload immediately after the last
per-insn descriptor, present when the header's ``CST_FLAG_PROFILE`` bit
is set (§2, §3.1; Step 4.6).  The in-tree writer sets the flag
unconditionally — no plugin option clears it, so every trace this
tracer produces carries the block — but a reader still gates presence
through the flag exactly as it does for ``CST_FLAG_WP``; a producer
without the aggregation machinery may omit the block and clear the
bit.  It is run-aggregated, PGO-style profiling metadata: it never
affects deterministic replay, and a consumer that does not model
it simply skips the bytes.  Because the templates section is
serialized at segment finish (after all execution), these are
final run totals, not running snapshots.

::

   profile_block:
     exec_cp            ULEB   correct-path executions of this BB
     exec_wp            ULEB   wrong-path executions of this BB
     # exec_cp == exec_wp == 0 is valid: a pre-declared REP self-loop
     # sub-template, materialized at translation but emitted only when
     # the REP runs >= 2 iterations.  Never referenced by a body entry.

     # Terminal-branch per-target taken/not-taken counts.  Consumed
     # 1:1 with the template header's n_targets / target_pc list (same
     # order & length; n_targets is NOT repeated here, and the
     # not-taken edge is the header's fall_through_pc, also not
     # repeated).  "Terminal branch" = the BB's LAST insn (its first
     # and only branch by the true-BB definition; NOT the branch that
     # entered the BB).  Empty when the last insn is not a branch.
     #
     # The header target_pc list is CORRECT-PATH ONLY: note_target()
     # is never called during wrong-path simulation — that pool is
     # what the wrong-path resolver mines to choose a speculative
     # target, so folding speculative targets in would defeat it.  For
     # a non-indirect branch n_targets == 1 and the counts are the
     # terminal branch's aggregate CP/WP taken vs fall-through.  For an
     # indirect branch CP counts are per target; the WP taken/not-taken
     # aggregate is attributed to target[0] (no per-target WP
     # distribution is tracked).
     repeat n_targets:
       taken_cp         ULEB   CP execs that took this target
       nottaken_cp      ULEB   CP execs that did not (fell through, or
                               indirect: chose a different target)
       taken_wp         ULEB
       nottaken_wp      ULEB

     # Per-insn, template insn order, exactly num_insns records.
     repeat num_insns:
       memops_cp        ULEB   total mem-ops this insn issued (CP)
       memops_wp        ULEB   total mem-ops this insn issued (WP)
       pat_flags        u8     bit[1:0] CP access-pattern class
                               bit[3:2] WP access-pattern class
                                 resolve via encoding map
                                 "mem_access_pattern" (CST_PAT_*).
                                 Per-memop classification runs two
                                 complementary tests on the effective-
                                 address stream and tallies the tag
                                 into a per-insn histogram; the
                                 reported class is the ARGMAX bin:
                                 the regime the insn spends most of
                                 its lifetime in.

                                 Test 1 (POLYNOMIAL CHAIN, abs-
                                 magnitude).  Walk derivative levels
                                 0..K-1 where K = CST_PAT_POLY_DEPTH =
                                 4 and each level is the abs
                                 difference of the previous:
                                     level 0:  |delta_n|
                                     level k:  ||x_{k-1,n}| -
                                               |x_{k-1,n-1}||
                                 Convergence at level 0 (|delta_n| ==
                                 |delta_{n-1}|) ⇒ REGULAR; convergence
                                 at any deeper level ⇒ IRREGULAR.
                                 Abs at every level avoids the
                                 constructive-sign-compounding failure
                                 mode (e.g. 0,1,3,4,6,7 ⇒ |d|=1,2,1,
                                 2,1 ⇒ signed ddelta alternates ±1 yet
                                 |ddelta|=1 throughout ⇒ IRREGULAR).
                                 K=4 covers polynomial address streams
                                 up to degree 4.

                                 Test 2 (GEOMETRIC RESCUE).  At every
                                 level the polynomial walk descends
                                 past, run the exact-integer cross-
                                 multiply test
                                     |x_n| * |x_{n-2}| == |x_{n-1}|^2
                                 on the last three level-k magnitudes.
                                 A match anywhere overrides RANDOM to
                                 IRREGULAR.  Catches pure exponential
                                 and any polynomial-plus-exponential
                                 mixture up to polynomial degree K-2.
                                 Only consulted when the polynomial
                                 chain returned no convergence.

                                 Both tests are structural properties;
                                 there is no magnitude threshold, and
                                 a 1-byte and a 1-MiB constant stride
                                 both tally as REGULAR.  Numeric
                                 values resolved through the
                                 `mem_access_pattern` map, not pinned
                                 here:
                                 CST_PAT_NONE       no memory access
                                                    seen
                                 CST_PAT_REGULAR    dominant: |delta|
                                                    constant (incl.
                                                    stride 0, direction
                                                    reversals of the
                                                    same magnitude, and
                                                    the trivial 1–2
                                                    step default)
                                 CST_PAT_IRREGULAR  dominant: polynomial
                                                    chain converges at
                                                    level ≥1 OR
                                                    geometric rescue
                                                    fires at some
                                                    walked level
                                                    (e.g. cubic walk:
                                                    |Δ³d|=const; 2^n
                                                    walk: constant
                                                    ratio across
                                                    |d_n|,|d_{n-1}|,
                                                    |d_{n-2}|)
                                 CST_PAT_RANDOM     dominant: neither
                                                    test classifies —
                                                    needs degree-(K+1)
                                                    or higher
                                                    polynomial, or
                                                    non-poly non-geo
                                                    structure
                               (two trackers run a per-access bin
                                tally — a per-insn PC-keyed classifier
                                and a cross-insn page-keyed spatial
                                classifier — each takes its argmax,
                                and the LOWER, more-regular argmax
                                wins.  The exact heuristic is a
                                writer-side detail, not a wire
                                contract)
                               bit[4]/bit[5] CP/WP data-is-address —
                                 resolve via encoding map
                                 "profile_flag" (CST_PROFILE_ADDR_*);
                                 set when a loaded/stored value's 4 KiB
                                 page is one that a real CORRECT-PATH
                                 mem-op touched (page-set membership,
                                 not a min/max span; the page set is
                                 never populated from wrong-path
                                 mem-ops, even for the WP flag)
       if memops_cp > 0:
         lo_addr_cp     ULEB   lowest effective addr touched (CP)
         hi_addr_cp     ULEB   highest − lowest (CP)
       if memops_wp > 0:
         lo_addr_wp     ULEB   lowest effective addr touched (WP)
         hi_addr_wp     ULEB   highest − lowest (WP)

A branch BB exposes **both** of its terminal edges regardless of
what the correct path did: the template header's ``fall_through_pc``
(the not-taken / next-PC edge) and its ``target_pc`` list (the taken
edges).  Both are filled even when the correct path never took the
branch — the wrong-path resolver supplies the edge the correct path
didn't.  A non-indirect branch has exactly one ``target_pc`` (its
single taken edge); an indirect/return branch enumerates its
distinct correct-path-observed targets.  The profile block's
per-target ``{taken,nottaken}_{cp,wp}`` counts are the authoritative
CP/WP totals: for a single-target (non-indirect) branch they are
the terminal branch's taken-vs-fall-through split; for an indirect
branch the CP counts are per target and the WP aggregate sits on
``target[0]``.

7. Decoder Checklist
~~~~~~~~~~~~~~~~~~~~

See **Part I (Decoder Recipe)** above for the procedural walkthrough:
Steps 1-7 cover the same flow at byte granularity, with the names a
decoder reverse-looks-up in each encoding map (Step 3.3).

The header maps are the compatibility mechanism for custom traces. If a
future trace adds a register ID this build does not know or a new
generic opcode, the numeric value and its string name travel together
in the header member.
