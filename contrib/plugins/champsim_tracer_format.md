# champsim_tracer Binary Format — v1.2 Specification

Status: current. Matches the on-disk output of
[champsim_tracer_output.cc](champsim_tracer_output.cc) and the reference
decoder in [champsim_tracer_decode.py](champsim_tracer_decode.py).

File extension: `.wpt`.

### Changes from v1.1

v1.2 is an **incompatible bump**. The magic number changes from
`0x11545343` (`"CST\x11"`) to `0x12545343` (`"CST\x12"`); readers must
refuse files with the old magic.

Summary of on-disk changes:

1. WP event records carry a chain-relative **faulting-insn index**
   when `CST_WP_EVENT_FAULT` is set. See §3.1.2. This lets consumers
   (e.g. ChampSim) flag the specific wrong-path uop that took the
   synchronous exception (segfault, INT div, FP div, etc.) so that
   uop — and its dependent slice — never "completes". Instructions
   issued around the faulting insn (same BB, no dependency) still
   execute as on a real wrong path.

### Changes from v1.0

v1.1 was an **incompatible bump**. The magic number changed from
`0x10575054` (`"TPW\x10"`) to `0x11545343` (`"CST\x11"`); readers must
refuse files with the old magic.

Summary of on-disk changes in v1.1:

1. Templates section is **mandatory**. `CST_FLAG_HAS_TEMPLATES` has
   been removed.
2. Memory-allocation events are removed. `CST_FLAG_MEM_ALLOC` and
   `BODY_TAG_MEMALLOC` are gone.
3. Each per-insn template record carries explicit `n_loads` and
   `n_stores` counts (both `u8`). These describe how many load and
   store dyn-params the insn owns on a "normal" execution of the
   template.
4. A new per-insn flag bit `CST_INSN_FLAG_DYNAMIC_MEMOP` (bit 6 of the
   insn flags byte) marks an insn whose runtime `(n_loads, n_stores)`
   may differ entry-to-entry.
5. Each body entry carries a **dynamic-memop preamble** before its
   dyn-patch: for every template insn flagged `DYNAMIC_MEMOP`, a ULEB
   pair `(actual_n_loads, actual_n_stores)` in template-insn order.
   Non-dynamic insns use the template's static counts unchanged.
6. Dyn-params within an entry are ordered by `(insn_index, type)` with
   loads before stores per insn. There is no longer a separate
   `n_loads` field in the dyn-patch record: load/store classification
   is reconstructed positionally from the template schema plus the
   preamble.

---

## 1. Top-level file layout

```
 offset 0
 ┌──────────────────────────────────────────────────────────┐
 │  Header              (variable length, byte-aligned)      │
 ├──────────────────────────────────────────────────────────┤  ← body_off
 │  Body stream         (sequence of tagged records,         │
 │                        terminated by BODY_TAG_END)        │
 ├──────────────────────────────────────────────────────────┤  ← templates_off
 │  Templates section   (mandatory in v1.1)                  │
 ├──────────────────────────────────────────────────────────┤  ← EOF − 64
 │  Trailer             (exactly 64 bytes)                   │
 └──────────────────────────────────────────────────────────┘
                                                              EOF
```

All integers on disk are **little-endian**. All records are
**byte-aligned** (see §7). Integer variables marked *ULEB* and *SLEB*
are LEB128 per DWARF §7.6.

### 1.1 Constants

| Symbol              | Value                | Purpose                       |
|---------------------|----------------------|-------------------------------|
| `CST_MAGIC`         | `0x12545343`         | File magic `"CST\x12"` (LE u32) |
| `CST_TRAILER_MAGIC` | `0x12545343FFFFFFFF` | Trailer sentinel              |
| `CST_TRAILER_SIZE`  | `64` bytes           | Fixed trailer size            |

### 1.2 Header feature flags (`u8`)

```
 bit 0  CST_FLAG_MEM_DATA       Per-access memory data values present
 bit 1  CST_FLAG_REG_DATA       Per-insn source-register values present
 bits 2..7  reserved, must be 0
```

### 1.3 Body record tags (`u8`)

```
 0  BODY_TAG_END        End-of-body sentinel (closes the stream)
 1  BODY_TAG_ENTRY      Executed basic block (CP + optional WP chain)
```

---

## 2. Header

Byte-aligned, written once at the beginning of the file.

```
 ┌────────┬────────┬────────┬────────┐
 │ magic[0..3]  (u32 LE = 0x12545343) │   'C'  'S'  'T'  0x12
 ├────────┼────────────────────────────┤
 │ isa(u8)│ flags(u8)                  │   trace_isa (TraceISA), §1.2
 ├────────┴────────────────────────────┤
 │ cmdline_len : ULEB                  │
 │ cmdline     : bytes[cmdline_len]    │   /proc/self/cmdline, spaces-joined
 ├─────────────────────────────────────┤
 │ datetime_len: ULEB                  │
 │ datetime    : bytes[datetime_len]   │   "%Y-%m-%d %H:%M:%S" local
 ├─────────────────────────────────────┤
 │ comment_len : ULEB                  │
 │ comment     : bytes[comment_len]    │   user-provided (plugin arg)
 ├─────────────────────────────────────┤
 │ target_len  : ULEB                  │
 │ target      : bytes[target_len]     │   qemu target_name, e.g. "x86_64"
 ├─────────────────────────────────────┤
 │ thread_id   : ULEB                  │   currently always 0
 └─────────────────────────────────────┘
```

`body_off` (recorded in the trailer) is the byte offset of the first
record after the header.

---

## 3. Body stream

The body stream is a sequence of records, each beginning with a 1-byte
tag, terminated by exactly one `BODY_TAG_END`. Every record is
individually byte-aligned (trivially, since all fields are
byte/LEB/length-prefixed).

Because the templates section is mandatory in v1.1, consumers generally
read the trailer first, then the templates section, then replay the
body with full per-insn schema knowledge. A single forward pass is
still possible if the consumer seeks to `templates_off` before walking
the body.

### 3.1 `BODY_TAG_ENTRY` — basic-block execution record

```
 ┌──────────────────────────────────────────────────────────┐
 │ tag = 1                                   (u8)            │
 │ tid_delta                                 (SLEB)          │  CP template id
 │                                                             as delta from
 │                                                             previous ENTRY
 ├──────────────────────────────────────────────────────────┤
 │ cp_dynamic_memop_preamble    (§4.1, only if CP template    │
 │                                has any DYNAMIC_MEMOP insns) │
 ├──────────────────────────────────────────────────────────┤
 │ cp_dyn_patch                 (§4.2)                        │
 ├──────────────────────────────────────────────────────────┤
 │ if CST_FLAG_MEM_DATA:                                     │
 │   cp_mem_data_section        (length-prefixed, §5)         │
 ├──────────────────────────────────────────────────────────┤ │ if CST_FLAG_REG_DATA:                                     │
 │   cp_reg_data_section        (length-prefixed, §5.2)       │
 ├─────────────────────────────────────────────────────────── │ wp_chain_section             (length-prefixed, §3.1.1)    │
 ├──────────────────────────────────────────────────────────┤
 │ wp_events_section            (length-prefixed, §3.1.2)    │
 └──────────────────────────────────────────────────────────┘
```

`tid_delta` is `cur_template_id − prev_entry_template`, with
`prev_entry_template` initialized to 0.

A "length-prefixed section" is:

```
    section_len : ULEB   (byte count of payload that follows)
    payload     : bytes[section_len]
```

#### 3.1.1 WP chain section payload

```
    num_wp                : ULEB
    for i in 0..num_wp:
      wp_tid_delta                 : SLEB   (delta from running prev, init 0)
      wp_dynamic_memop_preamble    : §4.1   (only if wp template has DYN insns)
      wp_dyn_patch                 : §4.2
      if CST_FLAG_MEM_DATA:
        wp_mem_data_section : §5
      if CST_FLAG_REG_DATA:
        wp_reg_data_section : §5.2
```

#### 3.1.2 WP events section payload

Sparse list — one entry per WP block that faulted or hit unmapped code.

```
    num_events            : ULEB
    for i in 0..num_events:
      pos_gap             : ULEB      (insn positions skipped since prev+1)
      ev_flags            : u8
        bit 0  CST_WP_EVENT_TRANSLATION_UNAVAIL
        bit 1  CST_WP_EVENT_FAULT
        bits 2..7 reserved
      if ev_flags & CST_WP_EVENT_FAULT:
        fault_insn_index  : ULEB      (index of the faulting insn within
                                       the WP block's merged template,
                                       0-based, chain-relative)
```

Absolute position = `prev_event_pos + 1 + pos_gap`, with
`prev_event_pos` initialized to `-1`.

`fault_insn_index` identifies the single wrong-path instruction that
raised the synchronous exception (segfault, integer divide-by-zero,
FP divide-by-zero, privileged insn, etc.). Consumers MUST treat that
uop as non-completing: any instruction data-dependent on its result
must also be prevented from completing. Instructions issued around
the faulting insn (earlier in the same WP block, or later but
independent of the fault) execute normally — matching real
wrong-path hardware behaviour.

When `CST_WP_EVENT_FAULT` is clear (translation-unavailable only)
the field is absent.

### 3.2 `BODY_TAG_END` — body terminator

```
 ┌─────────────────────────────┐
 │ tag = 0              (u8)    │
 │ num_entries          (ULEB)  │  count of BODY_TAG_ENTRY records
 └─────────────────────────────┘
```

After `BODY_TAG_END` the body stream is complete; the templates
section follows immediately.

---

## 4. Dyn-param encoding

Dyn-params are the runtime memory-access addresses for a basic block.
On disk they are ordered by `(insn_index, type)` — for each
instruction, all loads precede all stores; instructions appear in
template order. Load/store classification is **not** written
explicitly; the consumer reconstructs it positionally using the
template's per-insn `(n_loads, n_stores)` schema, with the
dynamic-memop preamble overriding the schema for flagged insns.

### 4.1 Dynamic-memop preamble

For every template instruction flagged `CST_INSN_FLAG_DYNAMIC_MEMOP`,
in template-insn order, the entry carries a ULEB pair:

```
    for i in 0..num_insns:
      if insn[i].flags & CST_INSN_FLAG_DYNAMIC_MEMOP:
        actual_n_loads   : ULEB
        actual_n_stores  : ULEB
```

The preamble is emitted even when the entry's dyn-patch is UNCHANGED.
If the template has no dynamic-memop insns the preamble is empty
(zero bytes).

### 4.2 Dyn-patch record

```
 ┌─────────────────────────────────────────────────────────┐
 │ flags                                         (u8)       │
 │   bit 0  CST_DYN_FLAG_UNCHANGED                          │
 │                                                          │
 │ if flags == CST_DYN_FLAG_UNCHANGED:                      │
 │   (nothing else — reuse previously emitted array)        │
 │                                                          │
 │ else:                                                    │
 │   cur_len           : ULEB    (total dyn-param count)    │
 │   changed_len       : ULEB    (number of positions)      │
 │   for c in 0..changed_len:                               │
 │     pos_gap         : ULEB    (pos − prev_pos − 1)       │
 │     delta           : SLEB    (cur.value − prev.value,   │
 │                                with prev=0 if new pos)   │
 └─────────────────────────────────────────────────────────┘
```

Per-template "previous" state is maintained separately for CP and WP
and is keyed on `template_id`. On first sighting of a template
`prev_dyn` is empty, so every position appears in `changed_len` with
`delta = cur.value`.

`cur_len` must equal the sum over template insns of
`insn.n_loads + insn.n_stores`, where dynamic-memop insns' counts come
from the preamble and other insns' counts come from the template.

---

## 5. Memory-data section

Emitted only when `CST_FLAG_MEM_DATA` is set. One section per
dyn-param array (CP entry, each WP entry). Section is length-prefixed
(§3.1).

Payload = one record per dyn-param, **in the same order** as the
dyn-param array from §4:

```
    size_code : u8            0=1B  1=2B  2=4B  3=8B  4=16B
    value_lo  : bytes[min(sz,8)]      little-endian
    value_hi  : bytes[max(sz-8,0)]    little-endian (16-byte only)
```

A 0 `data_size` from the plugin is remapped to 1 byte (defensive).

---

## 5.2 Register-data section

Emitted only when `CST_FLAG_REG_DATA` is set.  One section per
finalized basic-block entry — both **CP** entries and each **WP**
entry within a CP entry's WP chain.  The section is length-prefixed
(§3.1).

### Layout

The section contains, in template walk order:

```
    for i in 0..tmpl.n_insns:
        for r in 0..tmpl.insn[i].n_src_regs:
            reg_snap_record
        for r in 0..tmpl.insn[i].n_dst_regs:
            reg_snap_record
```

Per-snap record:

```
    size_code : u8                0=4B  1=8B  2=16B
    delta_lo  : SLEB128            value_lo - state_lo[reg_id]
    delta_hi  : SLEB128            present iff size_code == 2
                                   value_hi - state_hi[reg_id]
```

Values are 64-bit little-endian halves of the register value
(`lo` = bytes 0..7, `hi` = bytes 8..15).  Records are byte-aligned;
no padding bits are introduced anywhere in the section.

### Decoder state

The decoder maintains two parallel arrays
`state_lo[256]` / `state_hi[256]`, indexed by `GenericRegId`
(§6's `src_regs[r]` / `dst_regs[r]`):

* Both arrays are initialised to **all zeros** at the start of the
  body stream (immediately after the header / before the first
  `BODY_TAG_ENTRY`).
* After reading `delta_lo` for `reg_id != REG_NONE`, the decoder
  updates `state_lo[reg_id] += delta_lo` (mod 2⁶⁴) and reports the
  updated value as the snap's absolute `lo`.  Likewise for
  `delta_hi` when `size_code == 2`.
* When `reg_id == REG_NONE` (an unbound operand slot, e.g. the
  index register of a base-only addressing mode), the decoder
  treats the deltas as raw values against a zero baseline and does
  **not** mutate any state slot.

CP entries share a single `cp_state_*` pair across the whole body
stream.  Each CP entry's WP sub-section gets a **fresh** pair of
state arrays seeded from the current `cp_state_*` at the moment the
WP chain begins; WP entries within that chain accumulate deltas
into this `wp_state_*` pair.  When the WP chain ends, `wp_state_*`
is discarded — wrong-path execution is rolled back by QEMU
(`qemu_plugin_cpu_state_restore()`) so its register effects must
not leak into the next CP entry.

This mirrors the §4 dyn-patch encoding model: each register-id slot
behaves like an independent counter, so loop-invariant or
infrequently-changing registers cost a single 0-byte SLEB after
their first capture.

### Capture semantics

* CP snapshots are taken *before* the issuing instruction executes,
  via a per-insn `R_REGS` callback.  Source and destination
  registers are both read pre-execution.
* WP snapshots are taken via a different mechanism: QEMU's
  `qemu_plugin_spec_mode_begin()` path forces `CF_MEMI_ONLY` on
  speculative TBs, which silently suppresses
  `qemu_plugin_register_vcpu_insn_exec_cb()` registration, so the
  CP per-insn callback never fires for WP fragments.  Instead, the
  plugin captures a *wide* snapshot of the entire vCPU register
  file before each `cpu_plugin_exec_tb()` call in the WP loop, and
  attributes the captured values to the per-insn slots of the
  just-translated fragment template.  Because spec mode also
  forces `CF_SINGLE_STEP|1` (one guest insn per fragment), this is
  semantically equivalent to a per-insn pre-execution snapshot.
* If the runtime register name is empty or unresolvable on the
  target, the writer emits a zero snap (`size_code=0`, `delta_lo=0`)
  which leaves the state slot unchanged.  Such cases are also
  logged to `unknown_regs.log` next to the trace.
* Hardware registers wider than 16 B (e.g. 32 B AVX, 64 B AVX-512)
  are truncated to their low 16 B and emitted with `size_code=2`.

### Validator usage

The validator recovers per-memop base/index values by walking the
template's §6 per-operand metadata to map an operand to its
`src_regs[r]` slot, then looking up the corresponding §5.2 snap by
position.  Effective-address recompute uses the displacement and
scale from §6 (not §5.2).

---

## 6. Templates section

Mandatory in v1.1. Written after `BODY_TAG_END`, at file offset
`templates_off` (see trailer).

```
 num_templates : ULEB
 for t in 0..num_templates:
   tmpl_len   : ULEB
   tmpl_bytes : bytes[tmpl_len]      ← buffered as §6.1 then length-prefixed
```

### 6.1 Per-template payload

```
 ┌────────────────────────────────────────────────────────┐
 │ template_id       (ULEB)                                │
 │ start_pc          (ULEB)                                │
 │ num_insns         (ULEB)                                │
 │ fall_through_pc   (ULEB)                                │
 │ sym_len           (ULEB)                                │
 │ symbol_name       bytes[sym_len]  (UTF-8, may be empty) │
 ├────────────────────────────────────────────────────────┤
 │ for i in 0..num_insns:                                  │
 │   pc_delta        (ULEB)   pc − prev_pc (prev=start_pc) │
 │   opcode          (u8)     GenericOpcode                │
 │   branch_type     (u8)     BranchType                   │
 │   flags           (u8)                                  │
 │     bit 0         CST_INSN_FLAG_BRANCH_COND             │
 │     bit 1         CST_INSN_FLAG_HAS_IMM                 │
 │     bits 2..5     sync_hint (4-bit SyncEventType)       │
 │     bit 6         CST_INSN_FLAG_DYNAMIC_MEMOP           │
 │     bit 7         reserved, 0                           │
 │   n_src           (u8)                                  │
 │   n_dst           (u8)                                  │
 │   src_regs[n_src] (u8 each)                             │
 │   dst_regs[n_dst] (u8 each)                             │
 │   n_loads         (u8)     default load count for insn  │
 │   n_stores        (u8)     default store count for insn │
 │   if has_immediate:                                     │
 │     immediate     (SLEB)                                │
 │   insn_size       (u8)                                  │
 │   insn_bytes      bytes[insn_size]                      │
 └────────────────────────────────────────────────────────┘
```

After delay-slot reordering performed by the writer, the branch (if
any) is always the last instruction of a template.

`n_loads` and `n_stores` are the per-insn default (most-common)
dyn-param counts. If the writer ever observes a different count for a
given insn, it sets `CST_INSN_FLAG_DYNAMIC_MEMOP` on that insn and
the runtime counts are carried in each entry's preamble (§4.1). The
template's `n_loads`/`n_stores` are the maximum observed across all
entries when `DYNAMIC_MEMOP` is set; they may exceed the per-entry
preamble values but never contradict them.

---

## 7. Trailer

Exactly 64 bytes at EOF. Seek-first consumers read this and jump to
the body and/or templates offsets.

```
 ┌─────────────────────────────────────────────────────────┐
 │ templates_off      (u64 LE)   offset of templates section │
 │ templates_count    (u64 LE)   number of templates        │
 │ body_off           (u64 LE)   offset of first body record│
 │ body_byte_count    (u64 LE)   bytes from body_off to end │
 │                                of BODY_TAG_END record    │
 │ trailer_magic      (u64 LE)   0x12545343FFFFFFFF         │
 │ zero padding to 64 bytes                                 │
 └─────────────────────────────────────────────────────────┘
```

---

## 8. Encoding primitives

All emitted through `BitWriter` (a thin byte buffer — see the audit
document):

| Primitive            | On-disk size                | Used for                      |
|----------------------|-----------------------------|-------------------------------|
| `bw_write_u8`        | 1 byte                      | Tags, flags, small counts     |
| `bw_write_u32_le`    | 4 bytes LE                  | Magic                         |
| `bw_write_u64_le`    | 8 bytes LE                  | Trailer fields                |
| `bw_write_uleb128`   | 1..10 bytes                 | Unsigned counts, offsets      |
| `bw_write_sleb128`   | 1..10 bytes                 | Signed deltas (template ids, dyn-param deltas, immediates) |
| `bw_write_bytes`     | `n` bytes                   | Strings, insn bytes, sub-sections |
| `bw_write_section`   | `ULEB(n) + n` bytes         | Length-prefixed sub-sections  |
| `bw_byte_align`      | 0 bytes (documented no-op)  | Self-documenting marker       |

See [champsim_tracer_format_audit.md](champsim_tracer_format_audit.md)
for the byte-alignment audit and the reasoning behind the no-op
`bw_byte_align`.
