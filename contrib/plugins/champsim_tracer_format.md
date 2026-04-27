# champsim_tracer Binary Format — v1.7 Specification

Status: current. Matches the on-disk output of
[champsim_tracer_output.cc](champsim_tracer_output.cc) and the reference
decoder in [champsim_tracer_decode.py](champsim_tracer_decode.py).

File extension: `.cst`.

### Changes from v1.6

v1.7 is an **incompatible bump**.  Magic changes from `0x16545343`
(`"CST\x16"`) to `0x17545343` (`"CST\x17"`); the trailer magic moves
in lock-step.  Readers must refuse files with the old magic.

The three independent dynamic-parameter sub-sections of v1.6 — the
variable-memop preamble (§4.1), dyn-patch (§4.2), mem-data (§5), and
reg-data (§5.2) — are replaced by **one unified delta_section** per
basic-block entry.  Each emitted record carries an explicit field-id,
so the wire format itself describes which dynamic field changed
rather than relying on positional schema ordering.

Wire layout per BB entry (CP and each WP entry, identical shape):

```
delta_section := length-prefixed sub-section (ULEB128 byte count)
  body :=
    n_records  : ULEB128
    record*    : { ins_pos_gap : ULEB128
                   field_id    : u8
                   delta       : SLEB128 (interpreted mod 2**128) }
```

Records are emitted in non-descending `(ins_pos, field_id)` order;
`ins_pos_gap` is the gap from the previous record's `ins_pos` (0 for
records on the same insn).  An absent `(template_id, ins_pos,
field_id)` triple means *unchanged from the most-recent correct-path
emission, or equal to the template default if never seen*.  The delta
is the unsigned 128-bit value `(cur − baseline) mod 2**128` interpreted
as signed; readers reconstruct `cur = (baseline + delta) mod 2**128`.

Decoder state: per-stream `cp_field_state` and `wp_field_state` maps
keyed by `(template_id, ins_pos, field_id) → u128`.  CP state persists
across the whole body.  At each CP entry, `wp_field_state` is forked
from the current CP state (snapshot copy) and used for that entry's WP
chain only; the next chain re-forks from CP, preserving the
"speculative state rolled back at chain end" invariant.

Field-ID space (mirrors `CST_FID_*` in
[champsim_tracer.h](champsim_tracer.h)):

| Range / FID  | Family            | Slots | Gated by         | Default              |
|--------------|-------------------|-------|------------------|----------------------|
| `0x00`       | `MEMOP_COUNT`     | 1     | —                | template static count |
| `0x01..0x10` | `LOAD_ADDR`       | 16    | —                | 0 |
| `0x11..0x20` | `STORE_ADDR`      | 16    | —                | 0 |
| `0x21..0x30` | `LOAD_DATA`       | 16    | `MEM_DATA`       | 0 |
| `0x31..0x40` | `STORE_DATA`      | 16    | `MEM_DATA`       | 0 |
| `0x41..0x50` | `SRC_REG`         | 16    | `REG_DATA`       | 0 |
| `0x51..0x60` | `DST_REG`         | 16    | `REG_DATA`       | 0 |
| `0x70`       | `INSN_BYTES_LO`   | 1     | `INSN_MUT`       | template low 8 bytes |
| `0x71`       | `INSN_BYTES_HI`   | 1     | `INSN_MUT`       | template high bytes |
| `0x72`       | `INSN_OPCODE`     | 1     | `INSN_MUT`       | template opcode |
| `0x73`       | `INSN_BRANCH_TYPE`| 1     | `INSN_MUT`       | template branch_type |
| `0x74`       | `INSN_FLAGS`      | 1     | `INSN_MUT`       | template flags byte |
| `0x75`       | `INSN_IMMEDIATE`  | 1     | `INSN_MUT`       | template immediate |
| `0x76`       | `INSN_SIZE`       | 1     | `INSN_MUT`       | template size |
| `0xFF`       | `EXTENDED`        | —     | reserved         | reader reads `ULEB(ext_id), SLEB(delta)` and skips |

`MEMOP_COUNT` is emitted only for variable-memop mnemonics (its
default is the template's static `(n_loads, n_stores)`, packed as
`(n_loads<<8) | n_stores`); fixed-memop mnemonics produce no record.
`INSN_*` records are reserved for a future SMC observer and are not
emitted by the current writer (no `CST_FLAG_INSN_MUT` set).

The record-emission rule is mechanical: walk the template
insn-by-insn; for each insn walk the descriptor table in ascending
field-id order; for each descriptor slot, if `extract()` returns true
and the value differs from the per-`(template_id, ins_pos, field_id)`
baseline, emit one record and update the baseline.  Adding a new
dynamic field is exactly one entry in `field_descriptors[]` plus one
`CST_FID_*` constant.

Header feature flags (§1.2) gain `CST_FLAG_INSN_MUT (1<<2)`, set when
the writer emits `INSN_*` records.  `CST_DYN_FLAG_UNCHANGED` (the
v1.6 dyn-patch shorthand bit) is removed: a same-template entry with
no observable changes naturally produces a zero-record delta_section
(`n_records = 0`, single ULEB byte).

§4 (Dyn-param encoding), §4.1 (preamble), §4.2 (dyn-patch), §5
(mem-data) and §5.2 (reg-data) below are **superseded** for v1.7;
they are retained only as historical reference.  The structural
sections (§1 file layout, §2 header — modulo magic and flags, §3
body framing — modulo the per-entry delta_section replacing the
four old sub-sections, §6 templates, §7 trailer) remain unchanged.

---

# champsim_tracer Binary Format — v1.5 Specification (historical)

The remainder of this document describes the v1.5 wire format.  For
v1.7 see the section above.

### Changes from v1.4

v1.5 is an **incompatible bump**.  The magic number changes from
`0x14545343` (`"CST\x14"`) to `0x15545343` (`"CST\x15"`); readers must
refuse files with the old magic.

Summary of on-disk changes:

1. New per-insn template flag bit `CST_INSN_FLAG_VARIABLE_MEMOP`
   (bit 6 of the template insn flags byte).  Set by the writer for
   mnemonics whose load/store count varies at runtime (e.g. x86
   REP MOVS/STOS/CMPS/SCAS, ARM LDM/STM, RISC-V Zcmp `cm.push/pop`,
   RVV / SVE gather/scatter).  The bit is sourced from the per-ISA
   mnemonic table at trace time — it is **not** inferred from
   observed runtime counts — which makes the variability decision
   stable, declarative, and auditable.

2. The per-entry memop count preamble (§4.1) is now emitted **only**
   for template insns with `variable_memop = true`.  Non-variable
   insns rely on the template's static `(n_loads, n_stores)` for
   their per-execution count and contribute zero preamble bytes.
   For non-variable insns the writer asserts that every observed
   (n_loads, n_stores) tuple equals the template's static count;
   any divergence is a misclassification bug — the mnemonic must
   be marked `MF_VARIABLE_MEMOP` in its ISA classification table.

   In typical workloads (no string-prefix or RVV/SVE insns) the
   preamble shrinks to **zero bytes per entry**, eliminating the
   v1.4 §4.1 overhead entirely.

### Changes from v1.3

v1.4 was an **incompatible bump** from v1.3 (same wire layout, but a
redundant per-insn `CST_INSN_FLAG_DYNAMIC_MEMOP` bit removed and the
source-only `RegSnap.size_code` field deleted).  See git history.

### Changes from v1.2

v1.3 is an **incompatible bump**. The magic number changes from
`0x12545343` (`"CST\x12"`) to `0x13545343` (`"CST\x13"`); readers must
refuse files with the old magic.

Summary of on-disk changes:

1. The mem-data section (§5) now encodes per-memop values as a
   single **SLEB128 delta** of the unsigned 128-bit value
   `(hi << 64) | lo` against the prior value at the same
   `(template_id, memop slot index)` position, rather than raw
   little-endian bytes.  This captures the locality typical of
   stores to loop variables, struct fields, and stack scribbles,
   where most values change by small integer increments.  A single
   SLEB byte covers a delta in `[-64, 63]`.  State is initialised to
   zero on the first appearance of each `(template_id, slot)` pair.

   The per-record `size_code` byte from earlier drafts is **gone**:
   SLEB is self-delimiting, so the value's encoded width is implicit;
   the *access* width (1B vs 8B etc.) is not carried on the wire and
   must be recovered from the template (§6) or the dynamic-memop
   preamble (§4.1) by any consumer that needs it.  CP and WP states
   are tracked independently because their memop slots map to
   different vaddrs.

2. The reg-data section (§5.2) likewise emits a single SLEB128
   delta per snapshot, against the unsigned 128-bit prior value
   `(hi << 64) | lo`.  No per-snap size byte is written; register
   width is implicit in `reg_id` (architecturally fixed per
   `GenericRegId`).

### Changes from v1.1

v1.2 was an **incompatible bump**. The magic number changed from
`0x11545343` (`"CST\x11"`) to `0x12545343` (`"CST\x12"`); readers must
refuse files with the old magic.

Summary of on-disk changes in v1.2:

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
5. Each body entry carries a **per-insn memop count preamble** before
   its dyn-patch: for every template insn with
   `n_loads + n_stores > 0`, a ULEB pair
   `(actual_n_loads, actual_n_stores)` in template-insn order.
   Insns that never have memops contribute no bytes.
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
| `CST_MAGIC`         | `0x15545343`         | File magic `"CST\x15"` (LE u32) |
| `CST_TRAILER_MAGIC` | `0x15545343FFFFFFFF` | Trailer sentinel              |
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
 │ magic[0..3]  (u32 LE = 0x15545343) │   'C'  'S'  'T'  0x15
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
 │                                has any insn with             │
 │                                variable_memop = true)        │
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
      wp_dynamic_memop_preamble    : §4.1   (only if wp template has variable_memop insns)
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
template's per-insn `(n_loads, n_stores)` schema (the static count
for non-variable insns, the per-entry preamble §4.1 for
`variable_memop` insns).

### 4.1 Per-insn memop count preamble

For every template instruction with `variable_memop = true` (bit 6
of the template insn flags byte), in template-insn order, the
entry carries a ULEB pair giving the actual per-execution memop
count:

```
    for i in 0..num_insns:
      if insn[i].variable_memop:
        actual_n_loads   : ULEB
        actual_n_stores  : ULEB
```

Insns with `variable_memop = false` contribute no bytes; their
load/store count for every entry equals the template's static
`(n_loads, n_stores)` exactly.  If the template has no
`variable_memop` insns at all, the preamble is empty (zero bytes).

The writer asserts that observed runtime counts for non-variable
insns match the template's static count; a mismatch indicates a
mnemonic-table misclassification bug.  Variable insns may emit any
`(actual_n_loads, actual_n_stores)` consistent with the entry's
total dyn-param count.

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

`cur_len` must equal the sum over template insns of the per-entry
preamble's `actual_n_loads + actual_n_stores` (with insns absent
from the preamble contributing zero).

---

## 5. Memory-data section

Emitted only when `CST_FLAG_MEM_DATA` is set. One section per
dyn-param array (CP entry, each WP entry). Section is length-prefixed
(§3.1).

Payload = one record per dyn-param, **in the same order** as the
dyn-param array from §4:

```
    delta : SLEB128       cur128 − prev128 of the unsigned 128-bit
                          value (hi << 64) | lo (zero baseline on
                          first appearance of (template_id, slot))
```

The value is treated as an unsigned 128-bit little-endian integer
(`lo` = low 8 bytes, `hi` = high 8 bytes; for accesses ≤ 8 B `hi` is
implicitly 0).  The delta is encoded as a single SLEB128 of
`(cur128 - prev128) mod 2**128`; the decoder recovers
`cur128 = (prev128 + delta) mod 2**128` and splits it back into
`cur_lo`/`cur_hi`.

The wire format carries **no per-record access-width byte**.  SLEB is
self-delimiting, so the value width is implicit.  The semantic access
width (1B vs 8B vs 16B, used by cache-line-split modeling and similar
consumers) is recovered from the template (§6) — the per-insn opcode
tells consumers the architectural memop width.  Consumers that do
not need width (e.g. ChampSim's address-recompute path) ignore this
distinction entirely.

The writer masks sub-8-byte stores to their low `data_size`-byte
window before computing the delta, so a `u8` store of `0xFF` is
treated as the integer `255` and not as `-1`.  State is tracked
separately for CP and WP per `(template_id, memop slot)`; both
states persist for the lifetime of the body stream.  Wrong-path
memory operations don't mutate guest memory, so WP delta encoding
compresses repeated speculative reads of the same vaddr to single
zero-deltas.

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
    delta : SLEB128       cur128 − prev128 of the unsigned 128-bit
                          register value (hi << 64) | lo (zero
                          baseline on first capture of reg_id)
```

Values are 64-bit little-endian halves of the register value
(`lo` = bytes 0..7, `hi` = bytes 8..15).  For 4B/8B regs `hi` is
implicitly 0; the prior `hi` half stays 0 across the whole stream
for those regs, so the delta naturally encodes only the low half.
For 16B regs the value is the unsigned 128-bit integer
`(hi << 64) | lo` and the delta is the single SLEB128 of
`(cur128 - prev128) mod 2**128`.  No size byte is carried on the
wire; register width is implicit in `reg_id` (each `GenericRegId`
is architecturally fixed in width).  Records are byte-aligned; no
padding bits are introduced anywhere in the section.

### Decoder state

The decoder maintains two parallel arrays
`state_lo[256]` / `state_hi[256]`, indexed by `GenericRegId`
(§6's `src_regs[r]` / `dst_regs[r]`):

* Both arrays are initialised to **all zeros** at the start of the
  body stream (immediately after the header / before the first
  `BODY_TAG_ENTRY`).
* After reading `delta` for `reg_id != REG_NONE`, the decoder
  reconstructs `cur128 = (prev128 + delta) mod 2**128` from the
  current state, splits it into `lo`/`hi` halves, and updates both
  `state_lo[reg_id]` and `state_hi[reg_id]`.
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
  target, the writer emits a zero-baseline snap (`delta=0`)
  which leaves the state slot unchanged.  Such cases are also
  logged to `unknown_regs.log` next to the trace.
* Hardware registers wider than 16 B (e.g. 32 B AVX, 64 B AVX-512)
  are truncated to their low 16 B before being encoded.

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
 │     bit 6         CST_INSN_FLAG_VARIABLE_MEMOP          │
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

`n_loads` and `n_stores` are the per-insn observed-max dyn-param
counts across the entire body stream.  When non-zero, every body
entry's preamble (§4.1) carries the per-entry actual counts for
this insn.  The per-entry counts may be zero or any value up to the
template maximum.

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
 │ trailer_magic      (u64 LE)   0x14545343FFFFFFFF         │
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
