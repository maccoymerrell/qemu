# champsim_tracer Binary Format

This document specifies the on-disk `.cst` stream written by
`champsim_tracer_output.cc` and decoded by `cst_decode`, and is the
canonical reference for both the format and the tracer's use of it.
The format is in its pre-release epoch, identified by `CST_MAGIC`
(`0x1D545343`).  See *Format Stability and Conformance* (below) for
what the epoch identifier fixes, the minimum a conformant trace must
carry, and the forward-compatibility rules that govern additive
evolution within the epoch.

All multi-byte fixed-width integers are little-endian. Variable-width
integers use DWARF-style LEB128:

```
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
```

Every fixed-width integer/float in this format is little-endian;
the recipe sometimes writes the explicit suffix form (`u32_le`,
`f64_le`) at a field for emphasis — it denotes exactly the same
encoding as the unsuffixed token above.

Strings are length-prefixed UTF-8 byte strings:

```
string := len:ULEB  bytes[len]
```

Length-prefixed sections use the same shape:

```
section := len:ULEB  payload[len]
```

Throughout the recipe, a field typed `: section` is therefore **two
reads**: first the `len:ULEB` byte-length prefix, then the `payload[len]`
bytes.  The step a `: section` field cross-references (e.g. "see Step
6.7") describes only the *payload* — the `len:ULEB` has already been
consumed by the `: section` framing at the use site, exactly as a
`: string` field reads its `len:ULEB` before its bytes.  The two are
distinct: `len` is the on-the-wire byte size of the section (what a
reader skips to reach the next one), independent of how many logical
records the payload then declares.

This spec is split into two parts.  **Part I** is a procedural
recipe for a decoder author: each step is "read N bytes, decode as
X, branch on Y."  Following the recipe in order is sufficient to
parse any well-formed `.cst` file; values are not interpreted, just
laid out byte-by-byte.  **Part II** is the reference for what each
field *means* semantically (opcode enums, FID semantics, replay
rules, etc.).  Sections in Part II are cross-referenced from the
recipe steps that produce the relevant bytes.

---

# Format Stability and Conformance

## The magic epoch

`CST_MAGIC` (`0x1D545343`) identifies the format epoch.  It is fixed
for the whole pre-release: the layout evolves within the epoch, but
every change is *additive* and leaves the magic untouched.  Additive
evolution needs no magic change because every numeric domain
resolves through the per-trace encoding maps and body records are
self-delimiting, so a reader built to this specification stays
correct across additive changes.  A structurally breaking change — a
different record shape, step order, or structurally-required field
set — bumps `CST_MAGIC`: the magic is the format-epoch identifier and
that bump is the signal for "not the same format".  A change of that
kind is expected only at a formal release.

## Forward compatibility (normative)

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
  body field-delta record is `ipos_delta:ULEB, fid:ULEB,
  delta:SLEB_WIDE` (plus, only for `CST_FID_EXTENDED`, a trailing
  `ext_payload:ULEB`).  A reader that does not recognise `fid` MUST
  still consume the whole record — the LEB framing fixes its length
  unambiguously — and continue.  This is the format's per-record
  extension point: new per-instruction observations are added as
  new field-IDs that older readers skip.
* **The body-tag space is closed.**  Top-level `BODY_TAG_*` records
  are not self-delimiting without knowing the tag, so a reader MUST
  reject an unknown `body_tag`.  A new record *kind* is therefore
  not an additive change; it requires a new epoch (a formal-release
  magic bump).  Extend per record via field-IDs, not new tags.

## Minimum conformant trace (normative)

A producer that lacks the optional information can still emit a
valid `.cst`.  The irreducible content a conformant trace MUST
carry:

* **Container:** a tar with one `header.cst*` and one `body.cst*`
  member; the body bracketed by the two `CST_MAGIC` markers.
* **Header:** magic; isa; flags; the three window ULEBs;
  `simpoint_weight` (`0.0` when not a simpoint); the four header
  strings (any may be empty); an encoding-maps section carrying at
  least the structurally-required names of Step 3.3 plus an
  (id → name) entry for every numeric value the trace uses; and the
  templates section.
* **Per template:** `template_id`, `start_pc`, `num_insns`,
  `fall_through_pc` (0 if the last insn is not a branch),
  `n_targets` (0 if not a branch), `symbol_name` (may be empty),
  and `num_insns` per-insn descriptors.
* **Per insn:** `pc_delta`, `opcode`, `branch_type`, `flags`,
  `n_src`, `n_dst`, `src_regs[]`, `dst_regs[]`, `max_dep_loads`,
  `max_dep_stores`, `insn_size`, `insn_bytes[insn_size]`.
* **Body:** a leading `BODY_TAG_THREAD_SWITCH`; one
  `BODY_TAG_ENTRY` per correct-path BB invocation; and for every
  memop an instruction issues, that memop's effective address
  (`CST_FID_LOAD_ADDR{k}` / `CST_FID_STORE_ADDR{k}`) together with
  the `CST_FID_N_LOADS` / `CST_FID_N_STORES` counts; a terminating
  `BODY_TAG_END` carrying the `BODY_TAG_ENTRY` count.

Everything else is optional and its absence is signalled in-band —
a producer omits it by clearing the gate, and a reader detects the
absence by the same gate:

| Optional content | Absent when |
|---|---|
| Load/store data *values* | `CST_FLAG_MEM_DATA` clear |
| Destination-register snapshots | `CST_FLAG_REG_DATA` clear |
| Per-template profile block (§6) | `CST_FLAG_PROFILE` clear |
| Per-insn dependency sub-block | insn's `CST_INSN_FLAG_HAS_DEP_BLOCK` clear |
| Immediate value | insn's `CST_INSN_FLAG_HAS_IMM` clear |
| Raw instruction bytes | `insn_size == 0` (disasm unavailable; opcode/regs still define semantics) |
| Vector lane masks | insn's `CST_INSN_FLAG_VEC` clear |
| Branch-target history | `n_targets == 0` |
| Symbol name | empty `symbol_name` |
| Wrong-path chain + events (per entry) | `CST_FLAG_WP` clear (both sections omitted from every ENTRY/IFRAME); with the flag set, an individual entry may still carry `num_wp == 0` |
| Validation IFRAMEs | record simply absent (pure redundancy) |

---

# Part I: Decoder Recipe

## Step 0: One-time preparation

A decoder needs three working data structures, all built from the
header member (Step 1):

* `template_by_id` — map from `template_id : u32` to a parsed
  `Template` (start_pc, num_insns, per-insn descriptors).
* `encoding_maps` — twelve maps (`opcode`, `branch_type`,
  `reg`, `field_id`, `header_flag`, `insn_flag`, `body_tag`,
  `wp_event_flag`, `metaflags`, `dep_block_flag`,
  `mem_access_pattern`, `profile_flag`), each
  `value : u64 → name : string`.  Built from the encoding-maps
  section in Step 1.  (Parsing is generic — Step 3 reads whatever
  maps the section lists — so this enumeration is the set the
  writer emits, not a closed set a decoder must hard-expect.)
* `ids` — the numeric IDs the recipe branches on, resolved by
  reverse-lookup of canonical names through `encoding_maps` (e.g.
  `ids.body_tag_entry = encoding_maps.body_tag["BODY_TAG_ENTRY"]`).
  These are the names the byte-level parse depends on; Step 3.3
  enumerates them and states which must always be present and which
  are required only when the construct they tag appears.  Each is
  also named alongside its `ids.<field>` use below.

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
2.13 warmup_end_arch_insns : ULEB
     Architectural CP-insn count, measured against the body's
     own BB-template `n_insns` values, at which the segment
     transitions from warmup to simulation phase.  A consumer
     walking BODY_TAG_ENTRY records and summing the referenced
     template's `n_insns` enters the simulation phase the moment
     that sum reaches this value.

     Why a separate field, not just `warmup_insns`: the segment
     boundaries (start, warmup, stop) are configured in
     BBV-equivalent TB-execution count, matching the BBV plugin
     and SimPoint clustering.  The body, by contrast, fans REP
     out into one record per architectural iteration, so the
     in-trace arch-insn count diverges from BBV count whenever
     REP MOVSB/STOSB/etc. fires in warmup.  Counting
     `warmup_insns` of body entries would put the consumer
     somewhere in the *middle* of warmup on REP-heavy phases.

     Sentinel ULEB-encoded `UINT64_MAX` = the warmup boundary
     was not crossed in this segment (the trace was cut short,
     e.g. by guest exit, before warmup elapsed; the whole
     trace is warmup).  0 = warmup ends immediately (no
     warmup configured, e.g. non-simpoint icount mode).
2.14 templates section := raw payload to end-of-member (no outer
     length-prefix; the templates section runs to the header
     member's EOF).  Decode per Step 4.
```

Reject the trace if any read attempts to read past the end of the
header member, or if @magic does not match.

## Step 3: Parse the encoding maps

The `encoding_maps_section` payload from Step 2.12 is itself
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
3.3  After all maps are read, resolve the names the recipe branches
     on into a fixed-shape `ids` struct by reverse-lookup.  The
     names fall into two groups, by when each must be present:

     (a) Structural, always required.  Every conformant trace
         exercises the constructs these tag, so a trace whose maps
         omit one is rejected here:
           body_tag:    BODY_TAG_END, BODY_TAG_ENTRY,
                        BODY_TAG_THREAD_SWITCH
           header_flag: CST_FLAG_PROFILE, CST_FLAG_WP
           insn_flag:   CST_INSN_FLAG_HAS_IMM,
                        CST_INSN_FLAG_HAS_DEP_BLOCK

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
           wp_event_flag:  CST_WP_EVENT_FAULT (iff a wrong-path
                                               event record appears)
           field_id:       CST_FID_EXTENDED   (iff an extended
                                               field-delta record
                                               appears)

     Every other name — all `opcode`, `branch_type`, `reg`,
     `metaflags`, `mem_access_pattern`, and `profile_flag` values,
     the remaining `header_flag` / `insn_flag` / `wp_event_flag`
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
```

## Step 4: Parse the templates section

The templates payload from Step 2.13 runs to end-of-member.
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

The body's first record is always a `BODY_TAG_THREAD_SWITCH`, so the
starting thread is stated explicitly rather than assumed.  It is an
ordinary delta from `prev_thread_id = 0` (no special-case base): a
reader that just applies thread-switch deltas from 0, like every
other delta in the format, gets the correct starting thread with no
extra knowledge.  `thread_id` is the guest vCPU index and is stable
for the whole run — the same vCPU keeps the same `thread_id` across
every segment.

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
       Emit a per-thread initial-regfile snapshot for `thread_id`.
       Each `bytes[width]` payload is little-endian (the producer
       normalises from target byte order before write), so decoders
       interpret it as a little-endian unsigned scalar of `width`
       bytes regardless of guest endianness.
6.4  ENTRY record:
       template_id_delta : SLEB
       cur_template_id = prev_entry_template_id + template_id_delta
       prev_entry_template_id = cur_template_id
       cp_delta_section   : section          ; see Step 6.7
       if (header.flags & header_flag.CST_FLAG_WP):
         wp_chain_section  : section          ; see Step 6.8
         wp_events_section : section          ; see Step 6.9
       ; when CST_FLAG_WP is clear both sections are absent and the
       ; entry has no wrong-path chain (num_wp treated as 0).
       seq_num += 1
       Emit a CP body entry tagged (seq_num, cur_template_id,
       prev_thread_id) carrying the cp_delta_section's decoded
       dyn_params + reg_snaps, the wp_chain_section's WPEntries,
       and the wp_events bits applied to those WPEntries.
6.5  IFRAME record (validation-only; producers may omit it):
       cp_delta_section   : section
       if (header.flags & header_flag.CST_FLAG_WP):
         wp_chain_section  : section
         wp_events_section : section
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
     ; The `: section` field in Step 6.4 already read this section's
     ; len:ULEB; the steps below decode payload[len].  `len` (bytes)
     ; and `n_records` (count) are independent — an empty section is
     ; len=1 / n_records=0 (the single byte IS the n_records=0 ULEB).
       n_records : ULEB
       ipos : u32 = 0                  ; reset at section start; not
                                       ; carried across sections
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

All memops are addressed through the slotted families
(`LOAD_ADDR[0..63]` / `STORE_ADDR[0..63]` and their `DATA`
counterparts); there is no overflow vector.  An instruction whose
dynamic memop count exceeds `CST_FID_SLOT_COUNT` (64) has the
excess dropped at the writer.

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
CST_FID_SLOT_COUNT     = 64               max memops / dst regs per insn
```

`CST_MAGIC` and `CST_FID_SLOT_COUNT` are the only numerically-fixed
constants in the format: a reader compares the magic literally, and
`CST_FID_SLOT_COUNT` is the per-family slot ceiling.  Every other
numeric ID — body tags, opcodes, branch types, register IDs, field
IDs, flag-bit positions — is resolved through the per-trace encoding
maps (§3.1) and is not pinned by this specification.  The body-tag
values the writer currently assigns are `BODY_TAG_END = 0`,
`BODY_TAG_ENTRY = 1`, `BODY_TAG_THREAD_SWITCH = 2`,
`BODY_TAG_IFRAME = 3`, and `BODY_TAG_REGFILE = 4`; a decoder obtains
them from the `body_tag` map, not from these numbers.

The body member begins with `CST_MAGIC` and ends with `CST_MAGIC`.  A
file is treated as truncated if the trailing magic is missing.  The
header member begins with `CST_MAGIC` (no trailing magic; the member
naturally ends after its templates section).

`CST_FID_SLOT_COUNT` is the per-family slot ceiling for the
field-delta sections (loads, stores, destination registers).  When
an instruction's dynamic memop count exceeds this cap, the
writer clamps the trailing memops and emits a warning to
`unknown_warnings.log`; there is no `EXTRA_*` overflow path (see
Reference §5.2).

Field-delta `fid` is a ULEB128.  Numeric field-IDs are
non-normative — readers consume the header's `field_id` encoding
map.  The writer typically packs the hot fields into the 1-byte
ULEB range, but the layout is its concern, not the format's (see
Reference §5.1).

On ISAs with an integer flags register (x86, AArch64), every insn
whose template writes that register also emits a canonical
ISA-agnostic Z/N/C/V/P byte under `CST_FID_METAFLAGS` in the per-insn
field-delta stream.  The byte is gated on `CST_FLAG_REG_DATA` and is
otherwise absent; on ISAs with no integer flags reg (RISC-V, MIPS)
the FID never appears.

The metaflags byte carries an ISA-agnostic condition-flags summary,
computed by the plugin via a per-ISA shuffle of the guest's native
flags register (not directly readable from QEMU).  Each flag is
resolved through the `metaflags` encoding map — the trace assigns the
bit, a reader never assumes a position:

- `CST_METAFLAGS_Z` — zero / equal
- `CST_METAFLAGS_N` — negative / sign
- `CST_METAFLAGS_C` — unsigned carry / borrow
- `CST_METAFLAGS_V` — signed overflow
- `CST_METAFLAGS_P` — parity (x86 only)

The guest-to-canonical correspondence is by flag, not by position: x86
`EFLAGS` CF→C, PF→P, ZF→Z, SF→N, OF→V; AArch64 `NZCV` (top nibble of
CPSR) N→N, Z→Z, C→C, V→V (no parity).

Readers reject any file whose magic disagrees with `CST_MAGIC`.

The MEM_DATA / REG_DATA bits are advisory hints about field
families — the field IDs still determine what actually appears in
each delta section.  CST_FLAG_PROFILE and CST_FLAG_WP are
structural: they gate the presence of whole blocks (the
per-template profile block — Step 4.6 / §6, and the per-entry
wrong-path chain + events sections — Steps 6.4–6.5), exactly as the
per-insn CST_INSN_FLAG_HAS_DEP_BLOCK gates the dep sub-block.  Resolve
every flag through the `header_flag` map — the trace assigns each bit,
a reader never assumes a position:

- `CST_FLAG_MEM_DATA` — LOAD_DATA / STORE_DATA may appear
- `CST_FLAG_REG_DATA` — DST_REG fields may appear
- `CST_FLAG_PROFILE` — per-template §6 profile block present
- `CST_FLAG_WP` — per-entry wrong-path chain + events present

Per-instruction template flags, resolved through the `insn_flag` map
(again: names, not fixed positions):

- `CST_INSN_FLAG_BRANCH_COND` — conditional branch
- `CST_INSN_FLAG_HAS_IMM` — carries an immediate
- `CST_INSN_FLAG_ATOMIC` — atomic / locked memory op
- `CST_INSN_FLAG_VEC` — per-operand lane masks emitted
- `CST_INSN_FLAG_LANE_PARALLEL` — lane k of each dst depends only on
  lane k of every src
- `CST_INSN_FLAG_HAS_DEP_BLOCK` — intra-instruction dep mask present
- `CST_INSN_FLAG_SYSTEM` — privileged (non-user) execution context;
  uniform across a template, always clear in user-mode traces

`CST_INSN_FLAG_SYSTEM` distinguishes the kernel instructions of a
system-mode trace (the traced-but-not-counted privileged execution of
the pinned process, per the marker count set) from its user
instructions.  It is uniform across a template — a true basic block
never straddles a privilege transition, since the transition
instruction (syscall / interrupt entry / return) seals the block.
User-mode traces, and traces predating the flag, omit the name from the
`insn_flag` map and never set the bit; a consumer resolves an absent
name as "always user".

`dep_block_flag` map (only inspected when `CST_INSN_FLAG_HAS_DEP_BLOCK`
is set on the per-insn flag byte), resolved through the
`dep_block_flag` map:

- `CST_DEP_BLOCK_HAS_REG` — dst_dep + store_data_dep present
- `CST_DEP_BLOCK_HAS_ADDR` — load_addr_dep + store_addr_dep present

Wrong-path event flags, resolved through the `wp_event_flag` map:

- `CST_WP_EVENT_TRANSLATION_UNAVAIL`
- `CST_WP_EVENT_FAULT`

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
a single TB due to translation-block granularity.  `simpoint_weight`
is the fraction of whole-program execution this segment represents
(`0.0` for a non-simpoint segment); a consumer rebuilds a
whole-program metric as the weighted sum over the per-simpoint
traces.

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
records inline in the body stream (see §4.6), not as part of the
`reg` encoding map.

The writer emits these maps:

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
| mem_access_pattern | CST_PAT_* template-profile access classes|
| profile_flag  | CST_PROFILE_* template-profile pat_flags bits |
+---------------+-----------------------------------------------+
```

The template profile block (§6) is self-describing through these
last two maps: resolve `pat_flags` bits[1:0]/[3:2] via
`mem_access_pattern` and bits[4]/[5] via `profile_flag` rather than
hard-coding the class meanings.

Consumers resolve numeric IDs through the maps in the trace.  The
writer populates each map with its full canonical name set; Step 3.3
states which names a conformant trace is actually required to carry.

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
Its first record is always a `BODY_TAG_THREAD_SWITCH` (§4.1), so the
starting thread is stated explicitly.

```
body stream:

  +------------------------------+
  | tag = BODY_TAG_THREAD_SWITCH |   always the first record
  | thread switch payload        |
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
| wp_chain_section                section          |  only if CST_FLAG_WP
+--------------------------------------------------+
| wp_events_section               section          |  only if CST_FLAG_WP
+--------------------------------------------------+
```

`previous_entry_template` starts at 0 and updates after each CP entry.
The current thread/vCPU ID comes from the most recent
`BODY_TAG_THREAD_SWITCH` record; because the body's first record is
always a thread switch (§4.1), an ENTRY is always preceded by one.

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

Events annotate the entry's wrong-path chain: an event whose resolved
index addresses a chain position identifies a wrong-path block that
faulted, could not be translated, or terminated the excursion at a
fault-dependent branch; an event whose resolved index lies past the
chain is chain-level and describes the unrealized first target of the
wrong path itself (see below).

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

`CST_WP_EVENT_FAULT` marks a wrong-path instruction whose synchronous
exception was suppressed (a speculative access must not fault the
guest): the instruction's result never materializes and consumers
prevent its execution on the wrong path.  Execution proceeds around
the fault — instructions not data-dependent on it run exactly as they
normally would, with the accumulated wrong-path register state.

`CST_WP_EVENT_DEP_BRANCH_KILL` marks the block at which the excursion
died because its terminating branch depends, transitively through
registers, on a faulted instruction's never-materialized result: the
branch outcome is unresolvable, so fetch past it is unknowable and the
chain ends there.  The bit only appears on a chain's LAST block, and
only in chains that also carry a `CST_WP_EVENT_FAULT` at or before it.
Dependence is tracked at register granularity (the ISA's integer-flags
register included); poison carried through memory (a poisoned store
forwarded to a later load) is not tracked.  Traces written before this
bit existed do not list `CST_WP_EVENT_DEP_BRANCH_KILL` in their
`wp_event_flag` encoding map; readers resolve it optionally.

The event index space extends one convention beyond the chain: a
resolved index `>= num_wp` does not address any encoded wrong-path
block — it is a **chain-level** event describing the excursion's first
target, which was never realized as a block.  The writer emits exactly
one form of chain-level event: on an entry whose wrong-path chain is
empty (`num_wp == 0`) because the excursion was kicked but its first
fetch could not complete — the target's translation is unavailable at
that point in execution (for example a software-managed-TLB ISA where
the refill exception cannot be taken speculatively, so real hardware
would also fetch nothing) — the section carries `num_events = 1`,
`pos_gap = 0`, `ev_flags = CST_WP_EVENT_TRANSLATION_UNAVAIL`.  This
makes the architecturally faithful 0-block chain explicit rather than
indistinguishable from an entry whose wrong path was never simulated.
Readers MUST accept a resolved index `>= num_wp`, apply the event to
the chain as a whole rather than to a block, and still consume
`fault_insn_index` when the FAULT bit is set.

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
| wp_chain_section                section          |  only if CST_FLAG_WP
| wp_events_section               section          |  only if CST_FLAG_WP
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

### 4.6 BODY_TAG_REGFILE

A `BODY_TAG_REGFILE` record carries a per-thread initial register-file
snapshot: the architectural register values for one thread at the
point its execution in this segment begins. It seeds a consumer's
register model so that destination-register snapshots (§5.4) and
metaflags reconstruct absolute values. It is not counted in
`num_entries` and does not advance any body counter.

```
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
```

A producer that does not capture initial register state emits no
`BODY_TAG_REGFILE` records; their absence is not an error.

## 5. Field-Delta Sections

Every CP block and every WP block has one field-delta section. This is
the sparse update stream for dynamic memory addresses, memory values,
register values, memory-operation counts, and instruction metadata.

```
delta_section payload:

  n_records : ULEB

  repeat n_records times:
    ipos_delta : ULEB        running ipos += ipos_delta
    fid        : ULEB        resolve through the "field_id" map
    delta      : SLEB_WIDE   scalar delta; plus a trailing
                             ext_payload:ULEB only when fid resolves
                             to CST_FID_EXTENDED
```

The running `ipos` cursor is **section-local**: decoders initialise
`ipos = 0` at the start of every delta section (one per CP block, one
per each WP chain entry, one per IFRAME) and add `ipos_delta` from each
record. It is **not** carried across sections — there is no rolling
per-BB or per-template ipos. The persistent state that *does* carry
across sections is the per-template field-state cell keyed by
`(template_id, ipos, field_id)` (see below); the wire-level `ipos`
cursor is just the in-section pointer used to address those cells.

Records are emitted in non-descending `(ipos, fid)` order. When two
records describe the same instruction, the later record has
`ipos_delta = 0`.

Every record is a scalar delta record:

```
scalar_delta := SLEB_WIDE

delta = current_value - baseline, modulo 2**512
current_value = (baseline + delta) mod 2**512
```

Scalar values are little-endian unsigned integers with a 512-bit cap.
The two's-complement modular delta is emitted as one signed LEB value.
Small 32-bit and 64-bit values still encode as short LEBs; wide vector
register and memory values can occupy up to 512 bits.  Every body
record is a scalar delta — there is no raw-vector / `EXTRA_*` record
shape; all memops are addressed through the slotted families.

Scalar delta records update persistent field state. State is keyed by
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
map (Reference §3.1) carries the (id → name) pair for every field
the trace uses, and decoders MUST look up fields by name there.
This section describes the field families the writer emits and the
encoding-cost intent behind the writer's ID assignment.

Field families (one canonical name each):

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

* **Width families** — the byte width of each captured value, for
  value-prediction consumers that need to know how many bytes a
  predicted register or memory value covers.  The width is not
  recoverable from the value itself (the `SLEB_WIDE` encoding is
  magnitude-suppressed, with no length prefix) and is not static
  across ISAs (RISC-V V element width is the runtime `SEW`; SVE
  register width follows the vector length), so it is carried as its
  own per-slot field:

  * **`CST_FID_LOAD_SIZE{k}`** / **`CST_FID_STORE_SIZE{k}`** — access
    byte width of load / store memop slot `k`.  Gated on
    `CST_FLAG_MEM_DATA` (they ride with `LOAD_DATA` / `STORE_DATA`).
  * **`CST_FID_DST_REG_WIDTH{k}`** — write byte width of
    destination-register slot `k`.  Gated on `CST_FLAG_REG_DATA`.

  Each is a per-`(template_id, ins_pos, slot)` sparse scalar with
  baseline default zero, so a fixed-width access emits one record at
  first observation and zero bytes thereafter, while a width that
  varies (RVV `SEW` / SVE `VL` changes) emits a delta only when it
  changes.  Values are clamped to `CST_MAX_WIDE_BYTES`.  These
  families post-date the others; a trace produced without them is
  well-formed and decoders treat their absence as "width not
  captured".

* **Vector lane-mask families** (four, one slot per operand, gated on
  the per-insn `CST_INSN_FLAG_VEC` bit — see §6 *Vector lane masks*):

  * **`CST_FID_SRC_LANE_MASK{k}`** — for source-register slot `k`
    (parallel to the template `src_regs` array): bit `j` set iff lane
    `j` of that source register participates as an input this
    execution.
  * **`CST_FID_DST_LANE_MASK{k}`** — for destination-register slot
    `k`: bit `j` set iff lane `j` of that destination is produced
    this execution.  Need not equal the src masks.
  * **`CST_FID_LOAD_DATA_LANE_MASK{k}`** — for load memop slot `k`:
    bit `j` set iff lane `j` of the value-receiving vector register
    takes its value from this particular load.
  * **`CST_FID_STORE_DATA_LANE_MASK{k}`** — for store memop slot `k`:
    bit `j` set iff lane `j` of the source vector register is drained
    by this particular store.

  Each is a per-`(template_id, ins_pos, slot)` sparse field whose
  baseline default is zero, emitted as a scalar delta exactly like
  the other slotted families — so a uniform mask costs one record at
  first observation and zero bytes thereafter, while a mask that
  moves per execution (RISC-V V `vl`, gather/scatter memop fan-out)
  emits a delta only when it changes.  Mask width is up to 64 lanes
  (ULEB on the wire; the common 2/4/8/16-lane cases stay one byte).

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
`ea = base + index_term + disp`, where `index_term` is
`index << shift_amount` for an addressing form that shifts the index
(the AArch64 register form) or `index * scale` for one that scales it
(the x86 SIB form) — the two are mutually exclusive. The synthesized
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
emits: `GEN_OP_INT_ALU_SHORT`, `GEN_OP_INT_ALU_LONG`,
`GEN_OP_FP_ALU_SHORT`, `GEN_OP_FP_ALU_LONG`, `GEN_OP_VEC_ALU_SHORT`,
and `GEN_OP_VEC_ALU_LONG`. They exist
as a coarse fallback for external trace writers that lack ISA-specific
opcode metadata: SHORT is a single-cycle ALU op; LONG is anything
that occupies a long-latency unit (multi-cycle multiplier, divider,
vector pipe, etc.). Consumer code should handle them so foreign
traces remain decodable; in-tree traces always carry the more specific
opcode classifications above.

#### REP-prefixed self-loop BBs (x86)

`BranchType` carries a dedicated value `BRANCH_REP` (resolved through
the `branch_type` map) for any template instruction whose Capstone
detail reports the REP / REPNZ
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

Each architectural REP iteration is its own body entry; the
iterations are never aggregated onto a single entry with
`N_LOADS = N`.  This keeps each REP insn's per-iteration memop
count within `CST_FID_SLOT_COUNT` for high-count REPs.

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
there is no `EXTRA_*` raw-vector escape.

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

Narrow accesses are masked to their low accessed bytes before
emission as a scalar delta. The current QEMU plugin mem-value API directly
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

### Vector lane masks

When `CST_INSN_FLAG_VEC` is set the writer emits the four
lane-mask field families (Reference §5.1).  They are **per
operand**, not a single replicated value, and **dynamic** —
delta-encoded like every other slotted field, so they cost bytes
only when they change:

* `SRC_LANE_MASK{k}` / `DST_LANE_MASK{k}` — which lanes of source
  slot `k` / destination slot `k` participate this execution.  The
  src and dst masks are independent (an element insert writes one
  dst lane while reading the rest as pass-through).
* `LOAD_DATA_LANE_MASK{k}` / `STORE_DATA_LANE_MASK{k}` — which lanes
  take their value from / are drained by memop slot `k`.  These are
  computed at run time from the memop's address and size relative to
  the access base and the vector element width, so a structure load
  that fans into several lanes via several memops, or an
  immediate-selected single-element insert/extract, produces the
  correct per-memop lane partition.

The active-lane count can be fixed by the instruction encoding
(x86/NEON/MSA — derivable statically) or read from a register at
execution time (RISC-V V `vl`; future x86 EVEX k-mask / AArch64 SVE
predicate).  This distinction is **writer-internal**: it only
decides where the writer reads the live-lane value from.  On the
wire there is no "static vs dynamic" kind — every family is just a
dynamic delta-encoded mask, and a consumer treats them uniformly.
A trace without `CST_INSN_FLAG_VEC` (scalar insns) carries no lane
masks; consumers then treat every lane as participating.

`CST_INSN_FLAG_LANE_PARALLEL` records that lane `j` of each dst
depends only on lane `j` of every src (true SIMD lanes); when clear
the lanes still participate but cross-couple (shuffles, broadcasts,
horizontal reductions).

### Lane-granularity dependency resolution

The dep block above is **coarse** — when an instruction has no
precise refiner its `dst_dep` / `store_data_dep` masks are the
all-to-all over-approximation.  A consumer recovers the precise
*per-lane* dependency by intersecting the coarse dep masks with the
per-operand lane masks and the address masks, all of which are on
the wire:

1. An input listed in `dst_dep[d]` that is a vector operand feeds
   destination `d` only on the lanes where its `SRC_LANE_MASK` (or
   `LOAD_DATA_LANE_MASK`) intersects `DST_LANE_MASK[d]`.  Zero
   intersection ⇒ that input does not feed that destination at all.
2. A src that appears only in a `load_addr_dep` / `store_addr_dep`
   mask feeds the destination only transitively through the memop
   (the destination depends on the load; the load address depends
   on that src) — it is not a direct data dependency.

Worked example — `pinsrd $3, 0xc(%rsp), %xmm0` (insert one dword
from memory into lane 3 of xmm0):

* `DST_LANE_MASK` for xmm0 = `{3}`; `SRC_LANE_MASK` for the
  pass-through read of xmm0 = `{0,1,2}`; `LOAD_DATA_LANE_MASK` for
  the load = `{3}`.
* Coarse `dst_dep` is all-to-all (rsp, xmm0, load, imm).
* Resolved: lane 3 of xmm0 depends only on the load (`{3}∩{3}`);
  the pass-through xmm0 read (`{0,1,2}∩{3}=∅`) does **not** feed
  lane 3; rsp feeds the load address only (shown via
  `load_addr_dep`), so xmm0 lane 3 ← load, load addr ← rsp.

The `cst_decode --show-lanes` / `--show-deps` renderer implements
exactly this reconstruction and is the reference for it.

`pc_delta` is relative to the previous instruction PC, with
`previous_pc = start_pc` for the first instruction. The branch, if any,
is the last instruction after the writer's delay-slot normalization.

### Template profile block

Appended to every template payload immediately after the last
per-insn descriptor (always present — there is no opt-in flag).
It is run-aggregated, PGO-style profiling metadata: it never
affects deterministic replay, and a consumer that does not model
it simply skips the bytes.  Because the templates section is
serialized at segment finish (after all execution), these are
final run totals, not running snapshots.

```
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
```

A branch BB exposes **both** of its terminal edges regardless of
what the correct path did: the template header's `fall_through_pc`
(the not-taken / next-PC edge) and its `target_pc` list (the taken
edges).  Both are filled even when the correct path never took the
branch — the wrong-path resolver supplies the edge the correct path
didn't.  A non-indirect branch has exactly one `target_pc` (its
single taken edge); an indirect/return branch enumerates its
distinct correct-path-observed targets.  The profile block's
per-target `{taken,nottaken}_{cp,wp}` counts are the authoritative
CP/WP totals: for a single-target (non-indirect) branch they are
the terminal branch's taken-vs-fall-through split; for an indirect
branch the CP counts are per target and the WP aggregate sits on
`target[0]`.

## 7. Decoder Checklist

See **Part I (Decoder Recipe)** above for the procedural walkthrough:
Steps 1-7 cover the same flow at byte granularity, with the names a
decoder reverse-looks-up in each encoding map (Step 3.3).

The header maps are the compatibility mechanism for custom traces. If a
future trace adds `REG_FOO = 246` or a new generic opcode, the numeric
value and its string name travel together in the header member.
