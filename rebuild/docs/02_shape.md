# ChampSim Tracer — Layer 2: the SHAPE

*Layer 2 of 3. This layer does two jobs at once, and the second is the hard one:*

1. **Describe the shape faithfully** — every mechanism and data structure the
   tracer needs, the data flow CP and WP, what it reads from QEMU and where and
   when (the QEMU boundary is its own tab, `02a_qemu_interface.md`).
2. **Reduce the shape to its bare form** — each mechanism gets a **keep / change /
   rework** verdict, with discernment about whether the current shape is the best
   for its task. A verdict is grounded in the reality design (Layer 1), the wire
   contract (`format.rst`), and the golden code as it actually stands — read in
   planning, never copied into the rebuild. By the end, the tapestry is set and
   each block is ready for Layer 3's per-function detail.

Receipts: `[arch]` = `architecture.rst`; `[fmt §…]` = `format.rst`; `[qm]` =
`qemu_modifications.rst` / tab 02a; `[hdr:f]` = a plugin header; `[intent §…]` =
Layer 1; `[git:sha]` = a golden commit; `[rule]` = a standing ruling. The golden
is a flawed reference: where a mechanism's current shape is a golden bug, the
verdict says so and §8 carries the cross-reference.

The **simplification thesis**, stated once up front because it governs half the
verdicts: **separate the capture model from the serialization.** The information
the trace must carry (Layer 1 §2–§3.6) is one thing; how bytes are written is
another, and today they are fused in a 4,853-line hand-rolled delta-encoder with
its own overlays, FID numbering, and two-pass decoder recipe. The bare form is a
**capture core** that produces a typed record model and a **pluggable
serialization backend** behind a seam — with a database/columnar backend
(tester point e) assessed as the primary, because it makes tester points a, b and
c free and deletes most of the encoder. §6 is where that lands.

---

## 1. The block diagram

```
                         ┌──────────────────────────── QEMU base (tab 02a) ───────────────────────────┐
                         │ decode facts · branch target+dir · per-access provenance · path-event queue │
                         │ spec-mode session · containment · vclock freeze · get_plugin_state · thread  │
                         └───────────────▲───────────────────────────────────▲──────────────────────────┘
                                         │ translation-time                   │ execute-time
   ┌─────────────────────────────────────────────────┐        ┌───────────────────────────────────────────┐
   │ TRANSLATE  (vcpu_tb_trans, once per TB)          │        │ EXECUTE  (vcpu_tb_exec, once per TB exec)   │
   │  · poison/byte-stability gate                    │        │  shared prologue: WP early-out · promote ·  │
   │  · fragment splitter  → tb_templates_ (CODE/SPEC)│        │    capture-mute latch · vclock freeze       │
   │  · qdep seating (QEMU dataflow) + vocabulary join│        │  ┌── PathBuilder step (per vCPU thread) ──┐ │
   │  · lane / synthetic-EA / branch-target statements│───────▶│  │ step_events: async-mute, foreign-ASID, │ │
   └─────────────────────────────────────────────────┘        │  │   pending-seal SWAP (the deferral)      │ │
                                                               │  │ tw_manage_window (segment open/close)   │ │
   capture sinks (per vCPU thread, TLS):                       │  │ step_seal: fault frames, SEAL WALK ─────┼─┐
     mem_access_recorder · reg_snap_collector ◀────────────────┤  └─────────────────────────────────────────┘ │
                                                               └───────────────────────────────────────────┘ │
                                         chain assembler (fragments → true BB) ◀──────────────────────────────┘
                                         bb_map_ (true-BB dictionary) ◀── commit
                                                    │
                            emit_finalized_bb ──────┼────────▶ WP simulator (synchronous nested exec_tb loop)
                                                    │              spec session · WPBBEntry chain · termination
                                                    ▼
                            BodyEntry  ──▶  OUTPUT (field-delta overlays, FID encoder)  ──▶ writer thread ──▶ .cst
                                                    ▲
                            templates section + profile block + encoding maps (header)
```

Two flow loops `[arch]`: **CP** (correct path) in `vcpu_tb_exec` walks the
*previous* TB's fragment list, attributes stats, folds into a true-BB chain, and
emits a body record. **WP** (wrong path) is a synchronous nested loop kicked from
`emit_finalized_bb` that enters spec mode, redirects the PC, and runs
`cpu_plugin_exec_tb` to the `wpdepth` budget, then restores. Three locks:
`exec_lock` (serialises the CP step incl. nested WP), `data_lock` (cache
mutations inside that window), `unknown_warn_lock` (sidecar log). `[arch:
Synchronization]`

**Load-bearing invariant to reason from, not around:** *TBs are not basic
blocks.* The fragment splitter partitions each QEMU TB at non-final branch
terminators; the chain assembler folds fragments across TBs into true BBs sealed
at the next branch. Always reason about true BBs. `[intent][arch: tb-vs-true-bb]`

---

## 2. Translation path

| Mechanism / structure | What it is | Verdict |
| --- | --- | --- |
| **`vcpu_tb_trans`** | once-per-TB translation callback; runs poison/byte-stability gate, fragment splitter, qdep seating, vocabulary join, lane/EA/branch-target statements | **KEEP** — the amortised classification cost `[arch: Performance]` |
| **Poison / byte-stability gate** | refuses a TB whose bytes don't decode (`qemu_plugin_insn_undecoded`) or changed since first sighting; CP heals, SPEC only reads; content-hashed, flush-persistent | **KEEP** — reality-forced (what the CPU refuses to execute, the tracer refuses to record) `[arch: poison-detection]` |
| **Fragment splitter** (`split_tb_into_fragments`) + **`TbTerminus`** (COMPLETE / BARE_BRANCH / NONE) | partitions a TB at mid-TB branch terminators; the unit the chain assembler folds | **KEEP** — the sound replacement for per-TB BB reasoning `[arch: tb-vs-true-bb]` |
| **`tb_templates_`** + **CODE/SPEC dedup indexes** (`tb_chain_dedup_`, `spec_chain_index_`) | per-translation fragment templates (one per fragment), class-split so SPEC reclaims at flush and CODE persists; keyed `(asid_root, start_pc, canonical-insn-count)` | **KEEP mechanism, ASSESS the dual-index split** — the CODE/SPEC partition is a perf/lifetime optimisation; Layer 3 confirms whether a single generation-tagged index with a reclaim predicate is simpler at equal cost `[hdr:bb_template_cache.h]` |
| **qdep seating** (`champsim_tracer_qdep`) | reads per-instruction src/dst sets, per-access provenance and fold notes from QEMU's dataflow ABI; **consults no second decoder** | **KEEP** — the zero-Capstone spine; the single biggest correctness win of the current tree `[intent §3.1][02a §1]` |
| **Vocabulary table** (`champsim_tracer_vocabulary`) | one sorted array joining a QEMU-stated generic word → `GenericOpcode`/`BranchType`; refuses a word this build cannot read | **KEEP** — one table, infers nothing from operands `[arch: subsystem-map]` |

---

## 3. Template store (the dictionary)

The faithful shape is **seven maps** `[hdr:bb_template_cache.h]`: `tb_templates_`
(+ two dedup indexes), `bb_map_` (true BBs, serialised), `alt_map_`
(never-executed alternates, `static_templates=1`), `partial_bb_map_` (cut-short
extents), `retired_revisions_` (SMC), `revision_by_sig_` (A/B/A reuse),
`revision_slots_` (cap). Plus `SegRef` generation-stamping for cross-segment
handles, and **two** `commit_true_bb` variants (array vs reference, the second a
WP-hot-path copy-elision).

- **`BBTemplate`** (static shape: PC seq, generic opcode, branch type, src/dst
  reg IDs, immediate, raw bytes, dep block, lane masks, profile block) and
  **`bb_map_`** (keyed `(asid_root, start_pc)`; kernel code → shared
  `CST_KERNEL_ASID_ROOT` sentinel). **KEEP** — `template_id` identity, multi-ASID
  keying and the kernel sentinel are all reality-forced `[intent §3.2][fmt §6]`.
- **SMC revisions** (`resolve_true_bb` → mint a fresh `template_id`, retire the
  old by content signature, A/B/A reuse, per-PC cap). **KEEP the contract**
  (`[fmt §6][limits: SMC]`); **ASSESS the machinery** — three maps + two keys
  (`RevKey`, `BBKey`) for one feature. Layer 3 asks whether the content-signature
  index alone carries it.
- **Cut-short extents** (`partial_bb_map_`, keyed by `(asid_root, start_pc,
  n_insns, sig)`) exist because `bb_map_` is address-keyed and would hand back the
  *longer* template for a shorter run — the over-claim. **KEEP** — this is the
  honest-extent machinery that stops the close-time over-claim `[arch:
  cp-flow][hdr]`.
- **Alternates** (`alt_map_`, `static_templates=1`, off by default). **KEEP as
  optional** — it is already a no-wire-flag, body-byte-identical add-on `[fmt
  §… insn_flag; arch: static-templates]`.
- **Tester point (b) — template initial FID slots + first values.** Today a
  template declares its static shape and dep/lane masks but **not** the set of
  field-IDs its body entries will populate nor their initial values; the decoder
  learns slots as they first appear. The rebuild's template record gains a
  **declared initial field-state** (the FIDs this block emits + their baseline
  values) so a consumer pre-allocates per-block columns, and so a WP entry that
  never had a CP visit bases its deltas off the template's values rather than
  paying a first-observation cost (feeds tester c). **CHANGE** — a templates-
  section addition; magic bump at formal release (allowed pre-release). Under the
  DB backend (§6) it is the block's schema row and is free `[intent §3.2][fmt §6]`.

**Verdict summary:** the store's *contracts* are reality-forced and kept; the
*map count and the two commit variants* are the accreted-complexity the
simplification eye lands on, and Layer 3 is tasked to collapse what the capture
model does not actually require — most sharply once the serialization backend
(§6) owns dedup/columnarisation that some of these maps hand-roll.

---

## 4. CP flow, the PathBuilder, and the deferred structure (the headline rework)

**Faithful shape** `[arch: cp-flow, path-builder][hdr:path_builder.h]`:
`vcpu_tb_exec` fires once per executed TB. A shared prologue (WP early-out,
promote-to-CODE, capture-mute latch, vclock freeze, icount read) precedes the
PathBuilder step, split in two around window management because the gate order is
load-bearing:

- **`step_events`** (pre-window): async-mute window, foreign-ASID boundary, and
  the **pending-seal swap** — the current TB is promoted into the pending-seal
  slot and the previous occupant becomes the TB the seal phase walks.
- **`step_seal`** (post-window): fault-entry classification against the deferred
  prev, the shared **seal walk** (`collect_finalized_bbs`: fold fragments, resolve
  the terminal branch, update branch history, resolve the WP target), and emission.

Supporting structures, all **reality-forced KEEP**: the per-vCPU **scoreboard**
(inline stores of `current_pc` / `prev_start_pc` / `prev_fall_through` /
`TbTerminus`, so the executed tail is always known), the **chain assembler**
(fragments → true BB), the per-vCPU **fault ledger** (`CtxFrame` keyed `(thread,
window, resume_pc)`, read per owning thread), and the **async exclusion** window.
The fault-split program-order contract (executed prefix emitted *at* the fault,
continuation after, each piece declaring its range) is a Layer-1 §3.6 requirement
and is **KEEP**. `[arch: fault-excursions]`

### The deferred structure — why it exists and the rework

The **pending-seal slot defers TB *N* to the dispatch of TB *N+1*** because two
facts are only knowable one dispatch late:

1. **the tail instruction's post-execution register snapshot** — a destination
   value is read by the *next* instruction's callback; the TB's last instruction
   has no in-TB successor, so its snapshot waits for the next TB
   (`reg_snap_collector`'s `snap_prev_tail_dsts`); and
2. **which fragment executed, and its last PC** — resolved from the successor's
   inline `current_pc` store.

That one-dispatch lag is the **root of a whole class of machinery and of the
close-time fabrication bugs:**

- It forces the **`CstEmitLabel`** transfer register — because every body entry is
  emitted ≥1 dispatch after it ran, the `(thread, asid)` context label must be
  **stamped at promote** and carried to emit, lest the departed block publish
  under the incomer's label (ledger row 501). `[hdr:path_builder.h]`
- It forces the **`g_emit_fault_depth`** transfer register and its twice-per-seal
  re-stamp. `[arch: depth-pipeline]`
- At a close the slot holds a block with no coming successor, so historically the
  flush published the tail's register values from the wrong moment (**golden bug
  #79**) and a branch outcome it never observed (**golden bug #81**); the current
  tree papers these with `CST_BB_FLAG_BRANCH_UNRESOLVED` and the measured-extent
  emit, but the *root* is the deferral. `[git: 6494135e39][fmt §5.6, §5.7]`

**Already solved, do not re-open:** the branch *target* (direct) and resolved
*direction* are captured in-instruction by `branch_target_pc` /
`plugin_gen_record_branch_target` and the `59f8101261` hook — so the branch half
of the deferral is gone; only the register snapshot and fragment-resolution
remain. `[02a §1, §7]`

**REWORK (the archetype the maintainer named):** a **QEMU post-retirement
per-instruction delivery** (tab 02a §7) that hands the plugin an instruction's
committed destination values, the fact it retired, and its own next-PC *at that
instruction*. If the same signal also resolves which fragment executed, the
pending-seal slot, the `CstEmitLabel` stamp-at-promote dance, the fault-depth
re-stamp, and the close-time fabrication class all dissolve — the block is sealed
and emitted where it ran. Layer 3's first duty here is to answer, against the
code, **whether the signal removes the slot entirely or only the register half**;
the shape is designed to the "removes it entirely" target and falls back only if
the fragment-resolution cannot ride the same interface.

---

## 5. Capture sinks and the WP simulator

- **`mem_access_recorder`** — the `vcpu_mem_cb` sink, per-thread TLS vector (CP)
  and `g_wp_state.mem_accesses` (WP); caps at `CST_FID_SLOT_COUNT`=512 per
  direction. **KEEP** `[arch: subsystem-map][fmt §5.2]`.
- **`reg_snap_collector`** — destination-register post-exec values, read via the
  successor instruction's callback (the one-insn-late read) with a live
  post-fragment fallback for the WP trailing insn. **CHANGE with the rework (§4)**
  — the post-retirement interface replaces the one-insn-late read and the
  fallback with one in-instruction delivery `[arch: subsystem-map][02a §7]`.
- **Synthetic-EA** — prefetch/cache/TLB/`DC ZVA`/`CBO.ZERO` carry a stated EA
  computed from base/index at exec. **KEEP** `[fmt §5.2][02a §1]`.
- **WP simulator** (`champsim_tracer_wp.cc`) — synchronous nested loop: save
  state, `spec_mode_begin`, redirect PC, `cpu_plugin_exec_tb` to budget, restore.
  Emits a **`WPBBEntry`** chain moved into the owning `BodyEntry`. Termination
  conditions (budget / synthetic-data fault / syscall-class / translation-unavail
  / containment bail / flush-rerun) are a Layer-1 §3.5 contract. **KEEP**, on the
  02a wrong-path interface `[arch: wp-flow, wp-termination][02a §2]`.
- **Tester point (d) — REP/MOPS unrolled per iteration/access.** Both fan out to
  1-insn self-loop entries (REP per iteration counted from the count register;
  MOPS per memory access, bytes anchored). The *mechanism exists* and the golden
  fixes landed (`[git: 30e2246c0e, e1c3e4a238, 6217ac7b98, 5a6cb09d0a]`). **KEEP
  the contract**; Layer 3 states the correct unrolling (per-iteration register
  writes, one access per MOPS entry, WP single-steps REP and `wp_fan_self_loop`
  splits MOPS) and §8 flags the golden-bug history so validation is not confused
  `[arch: self-loop][qm — rep accounting; bulk-memory][intent §3.3]`.

---

## 6. Output and serialization — the seam, and tester a/b/c/e

**Faithful shape** `[fmt §1–§6]`: a POSIX ustar archive of two members
(`body.cst[.codec]`, `header.cst[.codec]`), optionally piped through
xz/zstd/gz. The body is a field-delta stream: per-`(template_id, ins_pos,
field_id)` persistent overlays (separate CP and WP, WP resolving WP→CP→default),
a running section-local `ipos` cursor, `SLEB_WIDE` scalar deltas, an 8192-entry
`field_id`→slot LUT, interleaved-by-slot FID numbering, and a two-pass decode
(apply deltas, then materialise against the executed range). The header carries
the encoding maps (names, not fixed numbers) and the templates + profile section.

This is **~4,853 lines of hand-rolled encoder** whose entire job is to optimise
size and read-efficiency ourselves. **The bare-form reduction is the seam:**

- **A capture-core record model** — templates, body entries (range, memops,
  reg-snaps, branch outcome), WP chains, context switches, profile — expressed as
  typed records, independent of how they are written.
- **A serialization backend behind that seam.** The current `.cst` delta-encoder
  becomes **one** backend (the reference/fallback). **Tester point (e): assess a
  database/open-format backend as the primary** so size and read-efficiency are a
  maintained library's job, not ours. Candidates, to be measured not asserted:
  - **SQLite** — streaming writes during a long run, ubiquitous, random-access +
    indexed; row-oriented so larger on disk, and WP laziness is a query not a
    layout.
  - **Parquet / Arrow (columnar)** — per-column compression and predicate
    pushdown give **lazy WP for free** (don't read the WP column group) and
    **low-FID-equivalence for free** (columns are typed, no ULEB FID width); but
    batch/row-group flush oriented, so the streaming-write ergonomics need care.
  - The experiment: one capture-core, two backends, measured on size / encode
    rate / decode RSS / consumer ergonomics (the ChampSim consumer reads via the
    tools today) against the custom `.cst`.
- **Tester point (a) — branch direction/target to low FIDs.** In the custom
  backend these two ride nearly every branch block yet sit in the 2-byte FID
  range; the rebuild assigns them `<128` (1-byte ULEB), the same ordering
  discipline the layout-intent already permits `[fmt §5.1]`. Under a columnar
  backend the concern **dissolves** (dedicated columns). **CHANGE** (custom
  backend) / **free** (DB backend).
- **Tester point (c) — WP as a lazy delta layer.** The WP→CP→default overlay
  resolution is already the golden design `[fmt §5]`, but WP rides **inline** in
  each body record, so a CP-only consumer still parses to skip it. The rebuild
  makes WP a **separately-decodable layer** (its own section/stream or column
  group) applied lazily on top of the CP overlay, its base-state overhead kept
  low by the template initial values (b). **CHANGE** (custom backend: hoist WP to
  its own section) / **free** (DB backend: separate table/column group).
- **Encoder internals** (BitWriter, `RawBuf`, the FID→slot LUT, the per-thread
  `FieldStateTable` overlays, the reg-handle/TLS caches). These are profiled
  micro-optimisations of the hand-rolled path `[arch: Hot-path
  micro-optimisations]`. **CHANGE/DELETE with the backend** — most do not survive
  a library-backed serialization; keep only what the capture core itself needs.
- **Writer thread** (bounded SPSC queue, one per segment) exists to keep a
  compressor stall off the guest clock. **KEEP** — a backend that blocks on I/O
  still needs the producer decoupled from the sink `[arch: async-writer]`.

**What the seam must preserve regardless of backend** (the capture contract, not
the encoding): byte-identical output for a region whether traced alone or as one
of N simpoints `[intent §3.7]`; the wire never fabricates an unobserved value
(unresolved branch declared, never guessed) `[fmt §5.6]`; no information loss
`[rule R12.1]`.

---

## 7. Identity, windows, tools (faithful, mostly KEEP)

- **Content-gate bit** (per vCPU, event-driven at every committed address-space
  change; marker bytes re-read at each latched vaddr; no root/ASID/pid stored as
  identity), **marker window**, **asid label index**, **`thread_id`** (guest
  thread, never vCPU), **privilege / SYSTEM bit**, **kernel-strand identity**. All
  **KEEP** — Layer-1 §3.6 reality-forced, on the 02a §4 interface.
- **Segment manager** + **simpoint manager** + the window modes (user:
  simpoint/icount/symbol/marker; system: marker-required, simpoint composed onto
  it). **KEEP** — §3.7 user-interaction contract; simpoint = N stand-alone traces
  in one pass `[intent §3.7][quickstart]`.
- **Stats / profile block / histogram buckets**. **KEEP** — profile is pure PGO
  annotation a consumer may drop `[fmt §6 profile]`.
- **Offline tools** (`cst_decode`, `cst_audit`, `cst_visualize`), the **external
  referee** (`cst_referee.py`, Capstone/LLVM, offline only), the **validator**.
  **KEEP, and re-home onto the serialization seam** — a tool reads the capture
  model through the backend, so a DB backend makes `cst_decode`/`cst_audit`
  thinner (the library does the parsing) `[intent §3.11][index]`.

---

## 8. Golden bugs & corrections baked in here

Stated at the mechanism they touch so validation is not confused later; each also
rides the lessons doc's ledger with its in-golden status:

- **REP/MOPS unrolling** (§5) — correct behaviour is per-iteration/per-access
  self-loop entries with per-iteration register writes; golden fixes landed
  (`30e2246c0e`, `e1c3e4a238`, `6217ac7b98`, `5a6cb09d0a`). The lessons doc
  verifies each is in golden, not only in the rebuild.
- **Branch direction/target criteria** (§4) — resolved runtime direction for
  coincident-edge branches (`59f8101261`/`572102ab1b`); MIPS BLEZ/BGTZ are
  conditional branches not calls (`adc7e2537a`); a CF_PARALLEL atomic's result is
  the loaded value alone (`646940f50f`).
- **Close-time fabrication** (§4) — stale tail register values (#79) and
  fabricated unresolved branch (#81); the deferred-structure rework removes the
  root, not just the symptom.
- **QEMU-side corrections** (tab 02a §8) — PAN debug-read, x86 lazy-flags,
  user-mode `probe_access`, device-timer re-arm, RISC-V itrigger, interrupt
  replay. Carried, not re-derived.

---

## 9. The bare-form picture (what Layer 3 builds against)

The simplified module set, after the verdicts above:

1. **Translate** — poison gate, fragment splitter, qdep seating, vocabulary join,
   in-instruction statements (branch target/dir, lane, synthetic-EA). *(kept)*
2. **Template store** — fewer maps than seven: the capture model needs a
   true-BB dictionary with SMC revisions, cut-short extents, and optional
   alternates; Layer 3 collapses the dedup/variant machinery the serialization
   backend now subsumes. *(kept contract, reduced machinery)*
3. **CP step** — **without the pending-seal deferral**: the post-retirement
   interface (02a §7) seals and emits a block where it ran, dissolving the
   `CstEmitLabel`/fault-depth transfer registers and the close-time fabrication
   class. *(reworked)*
4. **Capture sinks** — memops, in-instruction reg-snaps (reworked), synthetic-EA.
5. **WP** — the synchronous excursion on the 02a §2 interface, per-iteration
   REP/MOPS. *(kept)*
6. **Capture core → serialization seam** — a typed record model, a pluggable
   backend, a **database/columnar backend assessed as primary** (tester e), which
   makes branch-FID ordering (a), template initial values (b) and lazy WP (c)
   native rather than hand-rolled. *(reworked — the biggest deletion)*
7. **Identity / windows / tools** — kept, re-homed onto the seam.

**Open assessments Layer 3 must close against the code** (flagged, not pre-decided):
(i) does the post-retirement signal remove the pending-seal slot entirely or only
the register half (§4); (ii) which serialization backend wins the measured
experiment (§6); (iii) how far the template-store map count collapses once the
backend owns dedup/columnarisation (§3); (iv) whether the two containment paths
(`CF_FORCE_SLOW` vs portable `TLB_FORCE_SLOW`) unify (02a §7).

Nothing in the QEMU interface (tab 02a) is dropped by any of this; the reworks
**add** one interface (post-retirement delivery) and otherwise keep the hard-won
data-path and wrong-path surface intact.
