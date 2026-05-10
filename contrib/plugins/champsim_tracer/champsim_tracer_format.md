# champsim_tracer Binary Format

Status: current. This document describes the on-disk `.cst` stream
written by `champsim_tracer_output.cc` and decoded by `cst_decode`.
The tracer is pre-release; the on-wire layout below is the only
shape ever produced and the only shape `cst_decode` reads.

All multi-byte fixed-width integers are little-endian. Variable-width
integers use DWARF-style LEB128:

```
ULEB  unsigned LEB128
SLEB  signed LEB128
u8    one byte
u32   four bytes, little-endian
u64   eight bytes, little-endian
```

Strings are length-prefixed UTF-8 byte strings:

```
string := len:ULEB  bytes[len]
```

Length-prefixed sections use the same shape:

```
section := len:ULEB  payload[len]
```

## 1. File Layout

The file is written in streaming order, but seek-first consumers usually
read the fixed trailer first to find the body and template sections.

```
offset 0
  |
  v
+-----------------------------+
| Header                      |  variable length
| - fixed metadata            |
| - encoding maps             |
+-----------------------------+  body_off
| Body stream                 |  body_byte_count bytes
| - BODY_TAG_ENTRY records    |
| - BODY_TAG_END footer       |
+-----------------------------+  templates_off
| Templates section           |  templates_count records
+-----------------------------+  EOF - 64
| Trailer                     |  exactly 64 bytes
+-----------------------------+  EOF
```

The body refers to template IDs, and templates describe the static
instruction shape for each basic block. Dynamic fields in the body are
sparse deltas from the template default or from the most recent emitted
state for the same field.

## 2. Constants

```
CST_MAGIC          = 0x1A545343          bytes: 'C' 'S' 'T' 0x1A
CST_TRAILER_MAGIC  = 0x1A545343FFFFFFFF
CST_TRAILER_SIZE   = 64

BODY_TAG_END           = 0
BODY_TAG_ENTRY         = 1
BODY_TAG_THREAD_SWITCH = 2
BODY_TAG_IFRAME        = 3
BODY_TAG_REGFILE       = 4   (added v1.10)
```

The version byte rolled from `0x19` (v1.9) to `0x1A` (v1.10).  v1.10
introduced two related changes for multi-vCPU correctness:

  - The `reg` encoding map dropped its per-entry `(width, bytes)`
    suffix.  The header no longer carries any initial register-file
    snapshot.
  - A new body record `BODY_TAG_REGFILE` is emitted once per
    `(segment, thread_id)` pair, before that thread's first
    `BODY_TAG_ENTRY` in the segment, carrying that thread's initial
    register file as absolute values.

  - Field-state delta encoding became per-thread.  Each thread's
    `BODY_TAG_ENTRY` deltas are computed against that thread's own
    prior emission, not the cross-thread sequence.  Decoders maintain
    a per-thread `FieldStateTable`.

v1.9 readers will refuse v1.10 traces (magic mismatch); v1.10 readers
still accept v1.9 traces and ignore both new behaviours
appropriately.

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
bit 0      CST_INSN_FLAG_BRANCH_COND
bit 1      CST_INSN_FLAG_HAS_IMM
bits 2..5  sync_hint, a 4-bit SyncEventType value
bits 6..7  reserved, written as 0
```

Wrong-path event flags:

```
bit 0  CST_WP_EVENT_TRANSLATION_UNAVAIL
bit 1  CST_WP_EVENT_FAULT
bits 2..7  reserved, written as 0
```

## 3. Header

The header is byte-aligned by construction and is written once at the
start of the file.

```
+--------------------------------------------------+
| magic               u32  = 0x1A545343            |
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
+--------------------------------------------------+  body_off
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

`body_off` is stored in the trailer. A decoder can therefore verify that
it consumed the full header before starting the body stream.

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

In v1.9 the `reg` map carried a `(width_bytes, value_bytes)` suffix
per entry — a single initial register-file snapshot for the segment.
v1.10 removed that suffix; per-thread initial register files are now
emitted as `BODY_TAG_REGFILE` records inline in the body stream
(see §5).

The writer currently emits these maps:

```
+---------------+-----------------------------------------------+
| map_name      | Values described                              |
+---------------+-----------------------------------------------+
| opcode        | GenericOpcode values, GEN_OP_*                |
| branch_type   | BranchType values, BRANCH_*                   |
| sync_hint     | SyncEventType values, SYNC_*                  |
| reg           | GenericRegId values, REG_*                    |
| field_id      | CST_FID_* sparse delta field IDs              |
| header_flag   | CST_FLAG_* header bits                        |
| insn_flag     | CST_INSN_FLAG_* template flag bits            |
| body_tag      | BODY_TAG_* stream record tags                 |
| wp_event_flag | CST_WP_EVENT_* wrong-path event bits          |
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

Field IDs are one byte. Slotted families reserve 16 values each.

```
+----------------+----------------------+-------------------------------+
| Field IDs      | Family               | Meaning                       |
+----------------+----------------------+-------------------------------+
| 0x00           | N_LOADS              | current valid load slots      |
| 0x01..0x10     | LOAD_ADDR[0..15]     | load virtual addresses        |
| 0x11..0x20     | STORE_ADDR[0..15]    | store virtual addresses       |
| 0x21..0x30     | LOAD_DATA[0..15]     | load values, if MEM_DATA      |
| 0x31..0x40     | STORE_DATA[0..15]    | store values, if MEM_DATA     |
| 0x41..0x50     | reserved             | source-register-snapshot extension |
| 0x51..0x60     | DST_REG[0..15]       | destination register snapshots |
| 0x61           | N_STORES             | current valid store slots     |
| 0x62           | EXTRA_LOAD_ADDR      | raw load addr vector, slots 16+ |
| 0x63           | EXTRA_STORE_ADDR     | raw store addr vector, slots 16+ |
| 0x64           | EXTRA_LOAD_DATA      | raw load data vector, slots 16+ |
| 0x65           | EXTRA_STORE_DATA     | raw store data vector, slots 16+ |
| 0x66..0x6F     | reserved             | future memop metadata          |
| 0x70           | INSN_BYTES_LO        | low 8 bytes of instruction    |
| 0x71           | INSN_BYTES_HI        | high 8 bytes of instruction   |
| 0x72           | INSN_OPCODE          | GenericOpcode                 |
| 0x73           | INSN_BRANCH_TYPE     | BranchType                    |
| 0x74           | INSN_FLAGS           | per-insn template flags       |
| 0x75           | INSN_IMMEDIATE       | signed immediate              |
| 0x76           | INSN_SIZE            | instruction byte length       |
| 0xFF           | EXTENDED             | reserved escape; not currently used |
+----------------+----------------------+-------------------------------+
```

The header's `field_id` map carries the exact string associated with
each numeric field ID.

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

```
current n_loads = state(template, insn, CST_FID_N_LOADS)
current n_stores = state(template, insn, CST_FID_N_STORES)

valid load slots  = 0 .. n_loads-1
valid store slots = 0 .. n_stores-1
```

The first 16 slots use the scalar `LOAD_ADDR[0..15]` and
`STORE_ADDR[0..15]` fields. If an address field is absent for one of
these valid slots, the value is unchanged from that slot's current
baseline.

If `n_loads > 16`, the remaining load addresses are emitted in one
`EXTRA_LOAD_ADDR` raw vector for that instruction. If `n_stores > 16`,
the remaining store addresses are emitted in `EXTRA_STORE_ADDR`.
These raw vectors are present on every entry that has overflow memops;
they are not delta-coded and do not persist in field state.

### 5.3 Memory Data

When `CST_FLAG_MEM_DATA` is set, the data fields carry the observed
load/store value.

```
512-bit data value:

  little-endian unsigned scalar, up to 64 bytes
```

The first 16 memory data slots use scalar `LOAD_DATA[0..15]` and
`STORE_DATA[0..15]` delta records. Overflow data for slots 16 and above
is emitted in `EXTRA_LOAD_DATA` / `EXTRA_STORE_DATA` raw vectors when
`CST_FLAG_MEM_DATA` is set. Each overflow data vector has the same
number of values as the corresponding overflow address vector.

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

The templates section is mandatory and starts at `templates_off` from
the trailer.

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
|   n_loads         u8      zero; reserved default |
|   n_stores        u8      zero; reserved default |
|   immediate       SLEB    only if HAS_IMM        |
|   insn_size       u8                             |
|   insn_bytes      bytes[insn_size]               |
+--------------------------------------------------+
```

`pc_delta` is relative to the previous instruction PC, with
`previous_pc = start_pc` for the first instruction. The branch, if any,
is the last instruction after the writer's delay-slot normalization.

## 7. Trailer

The trailer is exactly 64 bytes and is always at EOF.

```
+--------------------------------------------------+
| templates_off      u64  offset of templates      |
| templates_count    u64  number of templates      |
| body_off           u64  offset of body stream    |
| body_byte_count    u64  bytes in body stream     |
| trailer_magic      u64  CST_TRAILER_MAGIC        |
| zero padding            through byte 63          |
+--------------------------------------------------+
```

The body byte range is:

```
[ body_off, body_off + body_byte_count )
```

The templates byte range starts at `templates_off` and ends at the
trailer.

## 8. Decoder Checklist

A robust decoder should follow this order:

```
1. Read the 64-byte trailer from EOF.
2. Validate trailer_magic.
3. Read the header from offset 0.
4. Stop header parsing exactly at body_off.
5. Load encoding maps from the header.
6. Decode templates at templates_off.
7. Replay the body stream from body_off for body_byte_count bytes.
8. Resolve opcode, branch, register, and field names through the maps.
```

The header maps are the compatibility mechanism for custom traces. If a
future trace adds `REG_FOO = 246` or a new generic opcode, the numeric
value and its string name travel together in the header.
