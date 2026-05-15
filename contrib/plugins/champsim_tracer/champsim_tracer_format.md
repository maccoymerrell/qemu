# champsim_tracer Binary Format

Status: current. This document describes the on-disk `.cst` stream
written by `champsim_tracer_output.cc` and decoded by `cst_decode`.
The tracer is pre-release; the on-wire layout below is the only
shape ever produced and the only shape `cst_decode` reads.

All multi-byte fixed-width integers are little-endian. Variable-width
integers use DWARF-style LEB128:

```
ULEB        unsigned LEB128, value fits in u64
SLEB        signed LEB128, value fits in i64
ULEB_WIDE   unsigned LEB128, value fits in u512 (8 little-endian
            limbs of u64).  Same continuation-bit format as ULEB;
            the only difference is that decoders accumulate into
            8 limbs, not one — used for EXTRA_*_DATA elements.
SLEB_WIDE   signed LEB128, value fits in i512 (sign extension via
            the high bit of the final byte's 7-bit payload).
            Used for field-delta values in the body stream
            (memop addresses, vector data, etc.).
u8          one byte
u32         four bytes, little-endian
u64         eight bytes, little-endian
```

Strings are length-prefixed UTF-8 byte strings:

```
string := len:ULEB  bytes[len]
```

Length-prefixed sections use the same shape:

```
section := len:ULEB  payload[len]
```

This spec is split into two parts.  **Part I** is a procedural
recipe for a decoder author: each step is "read N bytes, decode as
X, branch on Y."  Following the recipe in order is sufficient to
parse any well-formed `.cst` file; values are not interpreted, just
laid out byte-by-byte.  **Part II** is the reference for what each
field *means* semantically (opcode enums, FID semantics, replay
rules, etc.).  Sections in Part II are cross-referenced from the
recipe steps that produce the relevant bytes.

---

# Part I: Decoder Recipe

## Step 0: One-time preparation

A decoder needs three working data structures, all built from the
header member (Step 1):

* `template_by_id` — map from `template_id : u32` to a parsed
  `Template` (start_pc, num_insns, per-insn descriptors).
* `encoding_maps` — ten maps (`opcode`, `branch_type`,
  `reg`, `field_id`, `header_flag`, `insn_flag`, `body_tag`,
  `wp_event_flag`, `metaflags`, `dep_block_flag`), each
  `value : u64 → name : string`.  Built from the encoding-maps
  section in Step 1.
* `ids` — the well-known numeric IDs the decoder will dispatch on,
  resolved by reverse-lookup of canonical names through
  `encoding_maps` (e.g. `ids.body_tag_entry = encoding_maps.body_tag["BODY_TAG_ENTRY"]`).
  Reject the trace if any required name is missing — the wire
  format requires the writer to enumerate every name a decoder
  will dispatch on.  The required names are listed alongside each
  `ids.<field>` use below.

After Step 1 these structures are immutable for the remainder of
the decode.

## Step 1: Open the archive and decompress members

Treat the `.cst` file as an opaque POSIX ustar archive (512-byte
header per member, zero-padded to 512-byte boundaries, two trailing
zero blocks at end).

```
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
```

## Step 2: Decode the header member

After Step 1.4, the (possibly decompressed) header bytes are a flat
byte buffer.  Decode in order; the leading magic doubles as a
sanity check.

```
2.1  magic        : u32_le   ; must equal 0x1D545343 ("CST" + 0x1D)
2.2  isa          : u8       ; TraceISA enum (see Reference §2)
2.3  flags        : u8       ; CST_FLAG_* bitmask (Reference §2)
2.4  start_insn          : ULEB
2.5  warmup_insns        : ULEB
2.6  total_target_insns  : ULEB
2.7  command      : string
2.8  datetime     : string
2.9  comment      : string
2.10 target_name  : string
2.11 encoding_maps_section : section    ; see Step 3 for inner shape
2.12 templates section := raw payload to end-of-member (no outer
     length-prefix; the templates section runs to the header
     member's EOF).  Decode per Step 4.
```

Reject the trace if any read attempts to read past the end of the
header member, or if @magic does not match.

## Step 3: Parse the encoding maps

The `encoding_maps_section` payload from Step 2.11 is itself
self-describing.  Decode it into a fresh `encoding_maps` table.

```
3.1  n_maps : ULEB
3.2  repeat n_maps times:
       map_name  : string   ; "opcode" / "branch_type" / ...
       n_entries : ULEB
       repeat n_entries times:
         value : ULEB
         name  : string
       store (value → name) into encoding_maps[map_name].
3.3  After all maps are read, resolve the well-known names listed
     below into a fixed-shape `ids` struct.  Every name listed is
     mandatory; if a name is missing, reject the trace.
       body_tag:        BODY_TAG_END, BODY_TAG_ENTRY,
                        BODY_TAG_THREAD_SWITCH, BODY_TAG_IFRAME,
                        BODY_TAG_REGFILE
       field_id:        CST_FID_N_LOADS, CST_FID_N_STORES,
                        CST_FID_LOAD_ADDR0, CST_FID_STORE_ADDR0,
                        CST_FID_LOAD_DATA0, CST_FID_STORE_DATA0,
                        CST_FID_DST_REG0,
                        CST_FID_INSN_BYTES_LO, CST_FID_INSN_BYTES_HI,
                        CST_FID_INSN_OPCODE, CST_FID_INSN_BRANCH_TYPE,
                        CST_FID_INSN_FLAGS, CST_FID_INSN_IMMEDIATE,
                        CST_FID_INSN_SIZE, CST_FID_METAFLAGS,
                        CST_FID_EXTENDED
                        (no CST_FID_EXTRA_* in version 0x1D; the
                         overflow vectors retired with the slot-cap
                         raise — see Reference §5.2.)
       insn_flag:       CST_INSN_FLAG_BRANCH_COND,
                        CST_INSN_FLAG_HAS_IMM,
                        CST_INSN_FLAG_HAS_DEP_BLOCK
       dep_block_flag:  CST_DEP_BLOCK_HAS_REG,
                        CST_DEP_BLOCK_HAS_ADDR
       header_flag:     CST_FLAG_MEM_DATA, CST_FLAG_REG_DATA
       wp_event_flag:   CST_WP_EVENT_TRANSLATION_UNAVAIL,
                        CST_WP_EVENT_FAULT
       metaflags:       CST_METAFLAGS_Z/N/C/V/P
3.4  See Reference §3 for the semantic meaning of each map and ID.
```

## Step 4: Parse the templates section

The templates payload from Step 2.12 runs to end-of-member.
Decode by repeated outer-section unwrapping.

```
4.1  num_templates : ULEB
4.2  repeat num_templates times:
       tmpl_section : section          ; payload is one template
       parse tmpl_section.payload per Step 4.3.
4.3  Template payload (consumed from tmpl_section):
       template_id        : ULEB
       start_pc           : ULEB
       num_insns          : ULEB
       fall_through_pc    : ULEB
       symbol_name        : string     ; may be empty
       repeat num_insns times: one insn descriptor per Step 4.4
     After all insn descriptors are decoded, tmpl_section must be
     empty; reject otherwise.
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
       max_dep_loads      : u8         ; template-static MAX load count
                                       ; (runtime per-iter count rides on
                                       ; CST_FID_N_LOADS and can be smaller)
       max_dep_stores     : u8         ; template-static MAX store count
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
     Mask array sizes all come from the outer template header
     (n_dst, max_dep_loads, max_dep_stores) — the dep block itself
     carries only dep_block_flags + the masks.  HAS_REG and HAS_ADDR
     are independent: HAS_REG carries refiner-produced output deps
     (per-dst-reg, per-store-data), HAS_ADDR carries walker-produced
     per-memop address deps (which src_regs feed the load/store
     address — so the consumer can fire each memop without waiting
     on inputs irrelevant to its address).  See Reference §3 for
     the bit layout inside each mask.
```

Store every decoded template in `template_by_id` keyed by
`template_id`.  After this step the header member is fully parsed
and can be discarded.

## Step 5: Open the body member and verify magics

The body member is bracketed by two `CST_MAGIC` markers; the
trailing one is the truncation sentinel.  Verify both.

```
5.1  open the body member's decompressed byte stream.
5.2  lead : u32_le ; must equal 0x1D545343
5.3  body record stream := bytes between @lead and the trailing
     CST_MAGIC.  If you have the whole member in memory you can
     peek the last 4 bytes here; for streaming decoders, defer the
     trailing-magic check to Step 7.
```

## Step 6: Walk the body record stream

The body stream is a flat sequence of tagged records.  Track these
across the walk:

```
prev_entry_template_id : i32 = 0
prev_thread_id         : u32 = 0   (the current thread for the next ENTRY)
seq_num                : u32 = 0   (BODY_TAG_ENTRY counter)
```

Loop until a `BODY_TAG_END` is seen:

```
6.1  tag : u8
     dispatch on tag against the ids resolved in Step 3:
       ids.body_tag_thread_switch  → Step 6.2
       ids.body_tag_regfile        → Step 6.3
       ids.body_tag_entry          → Step 6.4
       ids.body_tag_iframe         → Step 6.5
       ids.body_tag_end            → Step 6.6 (terminates loop)
       any other value             → malformed; reject
6.2  THREAD_SWITCH record:
       thread_id_delta : SLEB
       prev_thread_id += thread_id_delta
       (No state output; the next ENTRY inherits prev_thread_id.)
6.3  REGFILE record:
       thread_id : ULEB
       n_present : ULEB
       repeat n_present times:
         gen_id : u8
         width  : u8
         bytes[width] : raw
       Emit a per-thread initial-regfile snapshot for `thread_id`
       (the bytes are in target-endian order).
6.4  ENTRY record:
       template_id_delta : SLEB
       cur_template_id = prev_entry_template_id + template_id_delta
       prev_entry_template_id = cur_template_id
       cp_delta_section   : section          ; see Step 6.7
       wp_chain_section   : section          ; see Step 6.8
       wp_events_section  : section          ; see Step 6.9
       seq_num += 1
       Emit a CP body entry tagged (seq_num, cur_template_id,
       prev_thread_id) carrying the cp_delta_section's decoded
       dyn_params + reg_snaps, the wp_chain_section's WPEntries,
       and the wp_events bits applied to those WPEntries.
6.5  IFRAME record (validation-only; producers may omit it):
       cp_delta_section   : section
       wp_chain_section   : section
       wp_events_section  : section
       Decode each section against fresh "nothing observed yet"
       overlays; the values reconstructed must match the
       immediately-preceding ENTRY exactly (template_id, dyn_params,
       reg_snaps, WP chain).  IFRAMEs do not advance
       prev_entry_template_id and do not emit a body entry.
6.6  END record:
       num_entries : ULEB
       must equal the total number of BODY_TAG_ENTRY records seen
       since the start of the body stream.  Exit the loop.
6.7  CP field-delta section payload:
       n_records : ULEB
       repeat n_records times: one field-delta record per Step 6.10.
     After all records are consumed the section payload must be
     empty.
6.8  WP chain section payload:
       num_wp : ULEB
       repeat num_wp times:
         wp_template_id_delta : SLEB
         wp_delta_section     : section    ; decode per Step 6.7
6.9  WP events section payload:
       num_events : ULEB
       prev_wp_index : i32 = -1
       repeat num_events times:
         pos_gap   : ULEB
         wp_index  = prev_wp_index + 1 + pos_gap
         ev_flags  : u8       ; wp_event_flag bits
         if (ev_flags & ids.wp_event_fault):
           fault_insn_index : ULEB
         apply ev_flags + (optional) fault_insn_index to
         wp_entries[wp_index] from Step 6.8.
         prev_wp_index = wp_index
6.10 One field-delta record:
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
```

`EXTRA_LOAD_ADDR` / `EXTRA_STORE_ADDR` / `EXTRA_LOAD_DATA` /
`EXTRA_STORE_DATA` are NOT part of this format version's `field_id`
map.  All memops are addressed through the slotted families
(`LOAD_ADDR[0..63]` etc.); an instruction whose dynamic memop count
exceeds `CST_FID_SLOT_COUNT` is rejected at the writer.

A SLEB_WIDE / ULEB_WIDE primitive: like LEB128 but the value is
read into up to 8 little-endian limbs (64 bits each, packing
7 bits per byte across limbs).  For SLEB_WIDE, if the final byte's
0x40 bit is set, sign-extend the remaining high bits to 1.

## Step 7: Verify the trailing magic

After Step 6 finishes (BODY_TAG_END was consumed), read 4 more
bytes from the body member's stream:

```
7.1  trail : u32_le   ; must equal 0x1D545343
7.2  the body member's stream must be exhausted at this point
     (no further bytes).  Reject otherwise.
```

If you streamed the body through a subprocess decompressor (Step
1.4 streaming path), this is also the right moment to call wait()
on the child and require a zero exit status.

---

# Part II: Reference

## 1. File Layout

A `.cst` file is a POSIX **ustar** archive carrying exactly two
regular-file members.  Each member is independently byte-aligned and
optionally compressed; the compression algorithm is encoded in the
member's filename suffix.

```
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
```

`<codec>` is one of `.zst`, `.xz`, `.gz`, `.bz2`, `.lz4`, or omitted
entirely (uncompressed).  When the tracer is run with `compress=<cmd>`
the writer streams each member's bytes through that command and renames
the in-archive member to match the resulting payload (e.g.
`body.cst.zst`).  The body is always written first so that header
finalisation can include the final template count.

Decoders should treat the archive as opaque, find both members by
prefix match (`body.cst*` and `header.cst*`), dispatch a decompressor
based on the trailing suffix, and parse each member as described
below.  There is no global file trailer and no global offset table:
each member is fully self-describing once you have its raw bytes.

The body refers to template IDs, and templates describe the static
instruction shape for each basic block. Dynamic fields in the body are
sparse deltas from the template default or from the most recent emitted
state for the same field.

## 2. Constants

```
CST_MAGIC              = 0x1D545343       bytes: 'C' 'S' 'T' 0x1D

BODY_TAG_END           = 0
BODY_TAG_ENTRY         = 1
BODY_TAG_THREAD_SWITCH = 2
BODY_TAG_IFRAME        = 3
BODY_TAG_REGFILE       = 4

CST_FID_SLOT_COUNT     = 64               max memops / dst regs per insn
```

The body member begins with `CST_MAGIC` and ends with `CST_MAGIC`.  A
file is treated as truncated if the trailing magic is missing.  The
header member begins with `CST_MAGIC` (no trailing magic; the member
naturally ends after its templates section).

`CST_FID_SLOT_COUNT` is the per-family slot ceiling for the
field-delta sections (loads, stores, destination registers).  When
an instruction's dynamic memop count would exceed this cap, the
writer clamps the trailing memops and emits a warning to
`unknown_warnings.log`; no `EXTRA_*` overflow path exists in this
format version (see Reference §5.2).

Version history
:    `0x1B`: original release.
:    `0x1C`: outer container becomes tar(body, header); 64-byte
     trailing trailer removed.  REP-prefixed string ops fan out
     per-iteration; `BRANCH_REP` added.
:    `0x1D` (current): field-delta `fid` is a ULEB128 instead of a
     fixed `u8`; `CST_FID_SLOT_COUNT` raised from 16 to 64; the
     `EXTRA_LOAD_ADDR` / `EXTRA_STORE_ADDR` / `EXTRA_LOAD_DATA` /
     `EXTRA_STORE_DATA` overflow fields are retired.  Numeric
     field-IDs are non-normative — readers consume the header's
     `field_id` encoding map.  The writer typically packs the hot
     fields into the 1-byte ULEB range, but the layout is its
     concern, not the format's (see Reference §5.1).

On ISAs with an integer flags register (x86, AArch64), every insn
whose template writes that register also emits a canonical
ISA-agnostic Z/N/C/V/P byte under `CST_FID_METAFLAGS` in the per-insn
field-delta stream.  The byte is gated on `CST_FLAG_REG_DATA` and is
otherwise absent; on ISAs with no integer flags reg (RISC-V, MIPS)
the FID never appears.

Canonical metaflags bit layout (1 byte; computed by the plugin via a
per-ISA bit shuffle, not directly readable from QEMU):

```
bit 0  CST_METAFLAGS_Z   zero / equal
bit 1  CST_METAFLAGS_N   negative / sign
bit 2  CST_METAFLAGS_C   unsigned carry / borrow
bit 3  CST_METAFLAGS_V   signed overflow
bit 4  CST_METAFLAGS_P   parity (x86 only)
bits 5..7                reserved, written as 0
```

x86 `EFLAGS` bit map: CF→C, PF→P, ZF→Z, SF→N, OF→V.  AArch64
`NZCV` (top nibble of CPSR) bit map: N→N, Z→Z, C→C, V→V; the P bit
is not set.

Readers reject any file whose magic disagrees with `CST_MAGIC`.  The
format is pre-release: there is one shape, and the tools support
exactly that shape.

Header feature flags are advisory. The field IDs still determine what
is actually present in each delta section.

```
bit 0  CST_FLAG_MEM_DATA      LOAD_DATA / STORE_DATA fields may appear
bit 1  CST_FLAG_REG_DATA      DST_REG fields may appear
bit 2  CST_FLAG_RESERVED_2    reserved, written as 0
bits 3..7                    reserved, written as 0
```

Per-instruction template flags:

```
bit 0  CST_INSN_FLAG_BRANCH_COND
bit 1  CST_INSN_FLAG_HAS_IMM
bit 2  CST_INSN_FLAG_ATOMIC          atomic / locked memory op
bit 3  reserved, written as 0
bit 4  CST_INSN_FLAG_VEC             per-slot lane bitmaps present
bit 5  CST_INSN_FLAG_LANE_PARALLEL   lane bitmaps line up by lane idx
bit 6  CST_INSN_FLAG_HAS_DEP_BLOCK   intra-instruction dep mask
bit 7  reserved, written as 0
```

`dep_block_flag` map (only inspected when `CST_INSN_FLAG_HAS_DEP_BLOCK`
is set on the per-insn flag byte):

```
bit 0  CST_DEP_BLOCK_HAS_REG    dst_dep + store_data_dep present
bit 1  CST_DEP_BLOCK_HAS_ADDR   load_addr_dep + store_addr_dep present  (phase 2)
bits 2..7  reserved
```

Wrong-path event flags:

```
bit 0  CST_WP_EVENT_TRANSLATION_UNAVAIL
bit 1  CST_WP_EVENT_FAULT
bits 2..7  reserved, written as 0
```

## 3. Header

The header member is byte-aligned by construction.  It is written last
(so the writer can include the final template count) but is logically
the first thing a decoder needs.

```
+--------------------------------------------------+
| magic               u32  = 0x1D545343            |
| isa                 u8   TraceISA                |
| flags               u8   CST_FLAG_* bits         |
| start_insn          ULEB                         |
| warmup_insns        ULEB                         |
| total_target_insns  ULEB                         |
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
```

`start_insn` is the architectural instruction count at which this
segment begins, anchoring the body records to a global instruction
timeline.  `warmup_insns` is the number of instructions at the front
of the trace meant to prime caches and branch predictors and not be
evaluated; it is zero outside simpoint mode and on simpoint runs with
no warmup configured.  `total_target_insns` is the configured length
of the segment — `warmup_insns + simulation_insns` for simpoint
segments, or `stop - start` for non-simpoint runs with an explicit
stop.  A value of zero means "unbounded" (non-simpoint runs with no
explicit stop trace until the program exits, so the targeted total is
not known at header-write time).  These three values describe the
*targeted* window; the actually-emitted record count may overshoot by
a single TB due to translation-block granularity.

Because the header lives in its own archive member, a decoder knows
the header end exactly: it is the member's payload size.  The
templates section runs from the byte immediately after the encoding
maps section through end-of-member.

### 3.1 Encoding Maps

The encoding map section makes the trace self-describing. Numeric IDs in
templates and dynamic fields can be resolved by reading the header rather
than assuming a fixed convention such as `241 == REG_ZERO`.

```
encoding_maps_section payload:

  n_maps : ULEB

  repeat n_maps times:
    map_name  : string       example: "reg"
    n_entries : ULEB

    repeat n_entries times:
      value   : ULEB         numeric value stored elsewhere in the trace
      name    : string       example: "REG_ZERO"
```

Per-thread initial register files are emitted as `BODY_TAG_REGFILE`
records inline in the body stream (see §5), not as part of the `reg`
encoding map.

The writer currently emits these maps:

```
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
| wp_event_flag | CST_WP_EVENT_* wrong-path event bits          |
| metaflags     | CST_METAFLAGS_* canonical flag bits           |
+---------------+-----------------------------------------------+
```

Consumers should use the maps in the trace when present. Built-in names
are only a fallback for files produced before this section existed.

## 4. Body Stream

Conceptually, every `BODY_TAG_ENTRY` record describes one *invocation*
of one true basic block on the architectural correct path.  Each
record carries: the template ID (which gives the static instruction
sequence), every per-instruction load and store address that fired
during this invocation (and value, if `MEM_DATA` is on), the
post-execution snapshot of every destination register written
(if `REG_DATA` is on), and the wrong-path chain — a sequence of
speculative basic-block invocations the CPU would have run if its
branch predictor had resolved the just-completed branch the other
way.  Body entries appear in correct-path execution order; the
field-delta encoding scheme below is a compression layer over
that conceptual picture, not a different shape of data.

The body stream is a sequence of tagged records ending in one footer.

```
body stream:

  +-------------------------+
  | tag = BODY_TAG_ENTRY    |
  | entry payload           |
  +-------------------------+
  | tag = BODY_TAG_THREAD_SWITCH |
  | thread switch payload   |
  +-------------------------+
  | tag = BODY_TAG_ENTRY    |
  | entry payload           |
  +-------------------------+
  | tag = BODY_TAG_IFRAME   |   (optional, validates the preceding ENTRY)
  | iframe payload          |
  +-------------------------+
  | tag = BODY_TAG_END      |
  | num_entries : ULEB      |
  +-------------------------+
```

`num_entries` must match the number of `BODY_TAG_ENTRY` records seen.
`BODY_TAG_IFRAME` records are not counted; they are pure
validation/resync redundancy.

### 4.1 BODY_TAG_THREAD_SWITCH

Thread switches are sparse records in the body stream. Normal basic
block entries inherit the current thread ID until the next switch record,
so traces do not pay a per-block thread field.

```
+--------------------------------------------------+
| tag = 2                         u8               |
| thread_id_delta                 SLEB             |
|   current_thread_id - previous_thread_id         |
+--------------------------------------------------+
```

`previous_thread_id` starts at 0. A decoder updates the current thread
state when it sees this tag and associates that thread ID with following
`BODY_TAG_ENTRY` records.

### 4.2 BODY_TAG_ENTRY

Each entry records one correct-path basic block and its optional
wrong-path chain.

```
+--------------------------------------------------+
| tag = 1                         u8               |
| template_id_delta               SLEB             |
|   current_template_id - previous_entry_template  |
+--------------------------------------------------+
| cp_delta_section                section          |
+--------------------------------------------------+
| wp_chain_section                section          |
+--------------------------------------------------+
| wp_events_section               section          |
+--------------------------------------------------+
```

`previous_entry_template` starts at 0 and updates after each CP entry.
The current thread/vCPU ID comes from the most recent
`BODY_TAG_THREAD_SWITCH` record, or 0 if no switch record has appeared.

### 4.3 Wrong-Path Chain Section

The wrong-path chain is a list of speculative basic blocks following
the CP block. Template IDs are delta-coded within the chain.

```
wp_chain_section payload:

  num_wp : ULEB

  repeat num_wp times:
    wp_template_id_delta : SLEB
    wp_delta_section     : section
```

Wrong-path field state is forked from the current correct-path state at
the start of the chain and discarded at the end of the entry.

### 4.4 Wrong-Path Events Section

Events identify wrong-path blocks that faulted or could not be
translated.

```
wp_events_section payload:

  num_events : ULEB

  repeat num_events times:
    pos_gap            : ULEB     index = prev_index + 1 + pos_gap
    ev_flags           : u8       CST_WP_EVENT_* bits
    if ev_flags has CST_WP_EVENT_FAULT:
      fault_insn_index : ULEB
```

`prev_index` starts at -1. `fault_insn_index` is the 0-based index of
the faulting instruction within that wrong-path block.

### 4.5 BODY_TAG_IFRAME

An IFRAME is a redundant absolute-encoded copy of the immediately-
preceding `BODY_TAG_ENTRY` body record. The writer emits it at an
arbitrary cadence (controlled by the `iframe_rate` plugin option, but
the wire format does not record the rate); decoders may use it to
cross-check that their delta-replay reconstructed the same view the
writer had, or skip it entirely.

```
+--------------------------------------------------+
| tag = 3                         u8               |
| cp_delta_section                section          |
| wp_chain_section                section          |
| wp_events_section               section          |
+--------------------------------------------------+
```

The IFRAME inherits the `template_id` of the preceding ENTRY (no
`template_id_delta` is encoded). Inside, every field-delta record is
encoded against `template_default` rather than against the persistent
overlay state, so the decoded value is absolute. When the CP-side
triggers an IFRAME, the entire body record is re-emitted in IFRAME
mode — including every WP-chain entry attached to that CP block; WP
entries are never IFRAME'd independently of their owning CP entry.

IFRAMEs MUST NOT advance `previous_entry_template` and MUST NOT update
the persistent `cp_field_state` / `wp_field_state` overlays — they
are pure validation/resync redundancy. The next `BODY_TAG_ENTRY`
continues from where the preceding regular ENTRY left off.

## 5. Field-Delta Sections

Every CP block and every WP block has one field-delta section. This is
the sparse update stream for dynamic memory addresses, memory values,
register values, memory-operation counts, and instruction metadata.

```
delta_section payload:

  n_records : ULEB

  repeat n_records times:
    ins_pos_gap : ULEB       current_insn_pos - previous_insn_pos
    field_id    : u8         CST_FID_* value; resolve through "field_id" map
    payload     : scalar_delta | raw_vector
```

Records are emitted in non-descending `(ins_pos, field_id)` order. When
two records describe the same instruction, the later record has
`ins_pos_gap = 0`.

Most records are scalar delta records:

```
scalar_delta := SLEB

delta = current_value - baseline, modulo 2**512
current_value = (baseline + delta) mod 2**512
```

Scalar values are little-endian unsigned integers with a 512-bit cap.
The two's-complement modular delta is emitted as one signed LEB value.
Small 32-bit and 64-bit values still encode as short LEBs; wide vector
register and memory values can occupy up to 512 bits.

`EXTRA_*` records use a raw vector payload instead of a scalar delta:

```
raw_vector:
  n_values : ULEB
  repeat n_values times:
    value : ULEB       unsigned raw value, not delta-coded
```

Only scalar records update persistent field state. State is keyed by
`(template_id, ins_pos, field_id)`:

```
first observation:
  baseline = template_default(template_id, ins_pos, field_id)

later observations:
  baseline = last_current_value_for_same_key

decode:
  current = (baseline + delta) mod 2**512
```

CP and WP each have their own overlay of `(template_id, ins_pos, field_id)`
→ value, both persisting for the whole body stream. WP records lookup
the WP overlay first, fall back to the CP overlay on miss, then to
the field's template default. Updates always write to the active
overlay (CP overlay for CP records, WP overlay for WP records); the
WP overlay never modifies CP state, so CP reconstruction is
unaffected by speculative side effects.

```
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
```

The WP overlay is persistent across chains: hot WP templates
visited from many CP entries delta against their prior WP-observed
value instead of paying the first-observation cost on every chain.
The CP overlay is unaffected by speculative records.

### 5.1 Field-ID Space

Field IDs are ULEB128 on the wire (Step 6.10).  Numeric IDs are
**not** pinned in the format spec; the header's `field_id` encoding
map (Reference §3.1) carries the (id → name) pair for every
well-known field used in this trace, and decoders MUST look up
fields by name there.  This section describes the field families
the writer emits and the encoding-cost intent behind the writer's
ID assignment.

Field families (one well-known name each):

* **`CST_FID_N_LOADS`** — count of valid load slots for this insn
  execution.  Encoded as a non-negative scalar delta against the
  prior observation of `(template_id, ins_pos)`; baseline default
  is zero.  Always emitted on entries whose insn has memops.

* **`CST_FID_N_STORES`** — analogous, for stores.

* **`CST_FID_METAFLAGS`** — canonical Z/N/C/V/P byte (see §2).
  Gated on `CST_FLAG_REG_DATA`; only emitted for insns whose
  template writes the ISA's integer-flags register, and only on
  ISAs that have one (x86, AArch64).

* **`CST_FID_LOAD_ADDR{k}`** for `k ∈ [0, CST_FID_SLOT_COUNT)` —
  load virtual addresses, indexed by memop slot.  Names are
  `CST_FID_LOAD_ADDR0`, `CST_FID_LOAD_ADDR1`, ... — the encoding
  map carries one entry per slot, and decoders look each up by
  name.  Address bits beyond u64 are silently truncated; address
  values are emitted as scalar deltas.

* **`CST_FID_STORE_ADDR{k}`** — analogous, for store addresses.

* **`CST_FID_LOAD_DATA{k}`** — load values, gated on
  `CST_FLAG_MEM_DATA`.  Up to 512 bits per slot (vector-register
  loads), emitted via the `SLEB_WIDE` scalar-delta path.

* **`CST_FID_STORE_DATA{k}`** — analogous, for store values.

* **`CST_FID_DST_REG{k}`** — destination-register post-execution
  snapshots, indexed by the template's `dst_regs` array position.
  Gated on `CST_FLAG_REG_DATA`.  Source-register values are not
  emitted on the wire — consumers reconstruct them from a regfile
  that the wp_event_flag stream + initial-state REGFILE records
  + DST_REG snapshots collectively define.

* **Instruction-metadata singletons** (cold; emitted only when
  the dynamic execution differs from the template baseline):
  `CST_FID_INSN_BYTES_LO`, `CST_FID_INSN_BYTES_HI`,
  `CST_FID_INSN_OPCODE`, `CST_FID_INSN_BRANCH_TYPE`,
  `CST_FID_INSN_FLAGS`, `CST_FID_INSN_IMMEDIATE`,
  `CST_FID_INSN_SIZE`.

* **`CST_FID_EXTENDED`** — reserved escape; reserve only.  The
  scalar-delta byte after this field-id's record is followed by
  one extra ULEB whose value is reserved.

**Layout intent (non-normative).**  The writer assigns numeric
IDs so the hot fields — slot counts, metaflags, and low-slot
memops + destination snapshots — collectively occupy IDs `< 128`
and therefore emit as a single ULEB byte.  High-slot families
and the cold instruction-metadata singletons fall into the
2-byte ULEB range (IDs 128..16383).  A future writer may
re-shuffle within these constraints (e.g., promote a different
hot field into the 1-byte range based on observed frequency)
without bumping `CST_MAGIC`; readers consume the per-trace
encoding map and stay correct.

The slot-family layout is **interleaved by slot** (slot `k` of
every family is co-located in the ID space) rather than
**family-then-slot** (all of one family before the next).  This
keeps low slots of every family in 1-byte territory and yields
strictly fewer total bytes than the alternative on every
realistic workload — see §5.2.

### 5.2 Memory Counts and Addresses

`N_LOADS` and `N_STORES` are ordinary sparse fields. Their baseline
defaults are zero. The writer derives current values by counting QEMU
memory callbacks for each instruction execution; opcode tables and
Capstone operand flags do not define these counts.

Three opcodes — `GEN_OP_PREFETCH`, `GEN_OP_CACHE_FLUSH`, and
`GEN_OP_TLB_FLUSH` — describe instructions that QEMU's TCG translates
to no memory op (software prefetch hints, cache-line clean / flush /
invalidate, TLB-entry invalidate). The writer synthesises a load
memop for these by decoding the Capstone operand at translation time
and reading base / index register values at execution time, computing
`ea = base + (index << shift_amount) * scale + disp`. The synthesized
EA appears in the same `LOAD_ADDR[0]` slot as a regular load and
contributes to `N_LOADS`. Opcode classification (PREFETCH / CACHE_FLUSH /
TLB_FLUSH) carries the semantic distinction; consumers that simulate
prefetch hints, cache-line evictions, or TLB shootdowns should
dispatch on the opcode rather than treating the EA as a normal load.
Instructions in these classes that have no memory operand (e.g. x86
`WBINVD`, AArch64 `IC IALLU`) emit no synthesized address and stay
classified under `GEN_OP_FENCE`.

#### LOAD / STORE as fall-through classifications

`GEN_OP_LOAD` and `GEN_OP_STORE` are fall-through buckets that say
"data motion happens, nothing else does." When an instruction does
something *more* than load-store-of-data, the opcode reflects that
more specific operation:

* **Atomic RMW where the data is mutated by an arithmetic op** —
  AArch64 `LDADD` / `LDCLR` / `LDEOR` / `LDSET`, RISC-V `AMOADD` /
  `AMOAND` / `AMOOR` / `AMOXOR`, x86 `XADD` — classify as the
  arithmetic op (`INT_ADD` / `AND` / `XOR` / `OR`) with `MF_ATOMIC`.
  The load and store are incidental to the modify.
* **Atomic exchange** — AArch64 `SWP` / `CAS{P}`, RISC-V `AMOSWAP` /
  `AMOCAS`, x86 `XCHG` / `CMPXCHG` — classify as `XCHG` with
  `MF_ATOMIC`. `XCHG` is reserved for instructions whose semantic IS
  swap.
* **Exclusive-monitor primitives that are individually just a tagged
  load or tagged store** — MIPS `LL` / `SC`, RISC-V `LR` / `SC`,
  AArch64 `LDXR` / `LDAXR` / `STXR` / `STLXR` — classify as
  `LOAD` / `STORE` with `MF_ATOMIC`. The monitor is a side effect
  on hardware state; the data is unmodified.
* **Loads / stores with implicit pointer arithmetic** — x86 string
  ops `LODS` / `STOS` / `INS` / `OUTS` advance `RSI`/`RDI` by the
  operand size on every iteration, so classify as `INT_ADD` even
  though the data motion is still occurring. AArch64 writeback
  `LDR` / `STR` / `LDP` / `STP` (`[Xn]!` or `[Xn], #imm`) are the
  ARM equivalent — Capstone collapses them with the non-writeback
  forms, so the per-ISA refiner detects the implicit base-register
  write at translation time and reclassifies to `INT_ADD`.
* **`MOV` / `CMP` are not fall-through** — they describe specific
  operations (data motion, comparison) and stay even when there is
  a side-effect pointer advance: x86 `MOVS{B,W,Q}` keeps `MOV`,
  `CMPS{B,W,Q}` / `SCAS{B,W,D,Q}` keep `CMP`.
* **Load-acquire / store-release** (AArch64 `LDAR` / `STLR` /
  `LDAPR` / `LDLAR` / `STLLR`, RISC-V `.aq` / `.rl` variants when
  paired with `LR` / `SC`) — memory ordering hints, not atomic
  primitives in the RMW sense. Classified as plain `LOAD` /
  `STORE` (without `MF_ATOMIC`); the ordering metadata is not
  currently surfaced on the wire.

#### Reserved fallback latency opcodes

The opcode space carries six reserved IDs the in-tree tracer never
emits: `GEN_OP_INT_ALU_SHORT` (61), `GEN_OP_INT_ALU_LONG` (62),
`GEN_OP_FP_ALU_SHORT` (63), `GEN_OP_FP_ALU_LONG` (64),
`GEN_OP_VEC_ALU_SHORT` (65), `GEN_OP_VEC_ALU_LONG` (66). They exist
as a coarse fallback for external trace writers that lack ISA-specific
opcode metadata: SHORT is a single-cycle ALU op; LONG is anything
that occupies a long-latency unit (multi-cycle multiplier, divider,
vector pipe, etc.). Consumer code should handle them so foreign
traces remain decodable; in-tree traces always carry the more specific
opcode classifications above.

#### REP-prefixed self-loop BBs (x86)

`BranchType` carries a dedicated value `BRANCH_REP` (= 6) for any
template instruction whose Capstone detail reports the REP / REPNZ
prefix (x86 string ops MOVS / STOS / LODS / CMPS / SCAS / INS /
OUTS).  These instructions are emitted as self-looping conditional
branches: target = the REP's own PC, fall-through = the next PC.
Consumers that model branch behaviour should treat `BRANCH_REP`
distinctly from `BRANCH_COND_DIRECT`:

* The taken-target is always the insn's own PC, so a predictor
  does not need to track target diversity for these branches.
* The not-taken path exits the architectural loop (ECX == 0 or a
  REPZ/REPNZ comparison terminator).

The body stream models each architectural iteration of a REP loop
as its own true-BB visit:

1. The BB that *enters* the REP loop ends at the first iteration's
   REP instruction.  Its body entry carries iter 1's load and/or
   store memops on the REP insn's slot, alongside the pre-REP
   setup insns' regular state.
2. Iterations 2..N each emit a separate body entry on a 1-insn
   self-loop sub-template.  The sub-template's single instruction
   is the REP itself with `BRANCH_REP` and `start_pc =
   fall_through_pc - insn_size` so the BB is structurally a
   self-loop.  Each entry's dyn_params carry exactly one
   iteration's worth of memops:

   - MOVS  → 1 load + 1 store
   - CMPS  → 2 loads
   - STOS  → 1 store
   - LODS  → 1 load
   - SCAS  → 1 load
   - INS   → 1 store (port → memory)
   - OUTS  → 1 load (memory → port)

3. Both the parent BB template and the sub-template appear in the
   templates section; their `template_id`s are independent and
   delta-encoded as usual in the body stream.

A regression in the fan-out (e.g. all N iterations aggregated onto
a single entry with `N_LOADS = N`) would surface in the trace as
the absence of the sub-template visits and a single overloaded
body entry — and would re-introduce the `EXTRA_*` overflow path
in the field-delta stream for high-count REPs.

```
current n_loads = state(template, insn, CST_FID_N_LOADS)
current n_stores = state(template, insn, CST_FID_N_STORES)

valid load slots  = 0 .. n_loads-1
valid store slots = 0 .. n_stores-1
```

The scalar `LOAD_ADDR[k]` and `STORE_ADDR[k]` fields address slots
`k ∈ [0, CST_FID_SLOT_COUNT)` directly.  If an address field is
absent for one of these valid slots, the value is unchanged from
that slot's current baseline.

If an instruction's dynamic `n_loads` or `n_stores` would exceed
`CST_FID_SLOT_COUNT = 64`, the writer is permitted to elide the
trailing memops past the cap and emit a warning to
`unknown_warnings.log` identifying the PC, opcode, and dropped-memop
count.  Consumers see only the first `CST_FID_SLOT_COUNT` memops in
that case; the elision is observable as the dynamic count being
clamped to the cap.  The wire format reserves no overflow path —
there is no equivalent of the `EXTRA_*` raw-vector escape used in
format versions `0x1B` / `0x1C`.

The 64-slot ceiling covers AVX-512 gather/scatter (≤ 16 lanes),
ARM SVE2 at VLEN ≤ 4096 (≤ 64 element loads), and RISC-V V at
LMUL × VLEN/SEW ≤ 64.  Workloads that genuinely need more either
fan the instruction out into multiple body entries (analogous to
the REP-prefixed self-loop fan-out for x86 string ops; see §5.2
below) or accept the writer-side clamp.

### 5.3 Memory Data

When `CST_FLAG_MEM_DATA` is set, the data fields carry the observed
load/store value.

```
512-bit data value:

  little-endian unsigned scalar, up to 64 bytes
```

Memory data values use the scalar `LOAD_DATA[k]` / `STORE_DATA[k]`
delta records, indexed identically to `LOAD_ADDR[k]` /
`STORE_ADDR[k]` (one data slot per memop slot, for
`k ∈ [0, CST_FID_SLOT_COUNT)`).  There is no separate overflow
path; the slot ceiling and overflow handling described in §5.2
apply uniformly to addresses and data.

Narrow accesses are masked to their low accessed bytes before delta or
raw-vector emission. The current QEMU plugin mem-value API directly
exposes values up to 128 bits; wider values are representable by
the wire format and by register snapshots, and can be populated by
capture paths that can provide up to 64 bytes.

### 5.4 Register Data

When `CST_FLAG_REG_DATA` is set, register fields carry post-execution
snapshots for the template's destination register slots only. Source
register identities remain in the template's `src_regs` array, but
source values are not emitted on the wire — destination values
strictly dominate (they cover every architectural write, so consumers
can derive any register's value at any point from the most recent
post-write observation, and there are typically fewer destinations
than sources per insn so the cost is lower).

```
template instruction:

  src_regs = [ REG_A, REG_B, ... ]   static source identities only
  dst_regs = [ REG_C, ... ]

delta fields for this instruction:

  CST_FID_DST_REG0  -> value of REG_C after execution
```

Capture timing: each per-insn destination snap is taken at the first
moment after the instruction's body completes — for non-tail insns
that's the pre-exec hook of the next canonical insn; for the tail
insn of every TB it's the next TB's tb_exec callback. Both points
guarantee the architectural register state reflects the just-finished
instruction's writes and not yet the next instruction's.

Register snapshots are scalar 512-bit values. The capture path copies
up to the first 64 little-endian bytes returned by
`qemu_plugin_read_register()`.

Register IDs are one-byte `GenericRegId` values. The trace header's
`reg` map gives the exact name for each value, including special values
such as `REG_ZERO`.

Current generic register layout:

```
+-------------+--------------------+
| Values      | Class              |
+-------------+--------------------+
| 0           | REG_NONE           |
| 1..64       | REG_GPR0..63       |
| 65..128     | REG_FPR0..63       |
| 129..192    | REG_VEC0..63       |
| 193..224    | REG_PRED0..31      |
| 225..230    | REG_SEG0..5        |
| 231..245    | compressed special |
| 250..254    | common specials    |
+-------------+--------------------+
```

The header map, not this table, is authoritative for decoding names.

### 5.5 Instruction Metadata

Instruction metadata fields default to the template instruction. They
are emitted only when the current execution differs from the current
baseline.

```
template instruction bytes/opcode/branch/immediate
          |
          v
first execution uses template defaults
          |
          v
INSN_* sparse records update only changed fields
```

This permits traces where an instruction's raw bytes or classification
changes without forcing a new template record.

## 6. Templates Section

The templates section is mandatory and is appended at the tail of the
header member, immediately after the encoding maps section.

```
templates section:

  num_templates : ULEB

  repeat num_templates times:
    tmpl_len   : ULEB
    tmpl_bytes : bytes[tmpl_len]
```

Each template payload is buffered so its byte length can be written
before the payload.

```
template payload:

+--------------------------------------------------+
| template_id      ULEB                            |
| start_pc         ULEB                            |
| num_insns        ULEB                            |
| fall_through_pc  ULEB                            |
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
```

When `flags & CST_INSN_FLAG_HAS_DEP_BLOCK`, an extensible dependency
sub-block follows the instruction bytes:

```
dep_block:
  dep_block_flags   u8        CST_DEP_BLOCK_HAS_REG | CST_DEP_BLOCK_HAS_ADDR
  if HAS_REG:
    dst_dep[d]            ULEB    for d in 0..n_dst-1
    store_data_dep[s]     ULEB    for s in 0..max_dep_stores-1
  if HAS_ADDR:
    load_addr_dep[l]      ULEB    for l in 0..max_dep_loads-1
    store_addr_dep[s]     ULEB    for s in 0..max_dep_stores-1
```

Mask array sizes (`n_dst`, `max_dep_loads`, `max_dep_stores`) all
come from the outer template header — the dep block itself carries
only the masks.  `max_dep_loads` / `max_dep_stores` are the
template-static MAX counts; the runtime per-iteration mem-op counts
ride on `CST_FID_N_LOADS` / `CST_FID_N_STORES` and can be smaller
(e.g. a conditional load that didn't fire) but never larger.

Bit layout inside each register/load mask:

```
bits [0, n_src)                            depends on src_reg[i]
bits [n_src, n_src + max_dep_loads)        depends on load_data[i - n_src]
bit  n_src + max_dep_loads                 depends on the immediate
```

Address masks omit the load-data bits because addresses are computed
before any load fires:

```
bits [0, n_src)                            depends on src_reg[i]
bit  n_src                                 depends on the immediate
```

Absence of `CST_INSN_FLAG_HAS_DEP_BLOCK` is the implicit all-to-all
over-approximation: every dst / store depends on every src / load.
Consumers that don't model intra-instruction dataflow can ignore
the block.

`pc_delta` is relative to the previous instruction PC, with
`previous_pc = start_pc` for the first instruction. The branch, if any,
is the last instruction after the writer's delay-slot normalization.

## 7. Decoder Checklist

See **Part I (Decoder Recipe)** above for the procedural walkthrough:
Steps 1-7 cover the same flow at byte granularity, with the well-
known names a strict-resolution decoder must reverse-look-up in
each encoding map.

The header maps are the compatibility mechanism for custom traces. If a
future trace adds `REG_FOO = 246` or a new generic opcode, the numeric
value and its string name travel together in the header member.
