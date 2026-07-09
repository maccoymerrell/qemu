# ChampSim Tracer rearchitecture plan

**Prepared for:** Maccoy Merrell (sole maintainer), for sign-off before any code is written.
**Scope:** synthesis of the three commissioned analyses (tangle map; event-stream architecture; template-store/data-shape redesign), re-verified against the working tree on `champsim-trace`. All paths relative to `/mnt/md0/QEMU/qemu`. Everything cited below was read in the current tree, not assumed. The wire format and `CST_MAGIC` are untouched by every phase.

The maintainer's verdict — "the wrong shape for the input and output it is trying to form" — is confirmed and is precisely diagnosable: the plugin's *output* is a causally-ordered stream of sealed true-BBs with attributes (depth, exclusion, merge identity), but its *input* today is a pile of lazily-sampled QEMU state (seq counters, one boolean, an ASID register, scoreboard slots) that must be re-woven into causal order at every TB boundary by position-sensitive gates. Each battle scar was a patch on that re-weaving. The right shape delivers the causality as data (an ordered event queue) and gives the re-weaving a single owner (a path-builder state machine), while the two supporting shape problems — template lifetime spread across three ad-hoc regimes, and a 3272-byte-per-instruction metadata struct — are fixed independently underneath.

---

## 1. Diagnosis — five root shape problems

### P1. Exit causality is reconstructed one TB late from proxy channels, instead of delivered as ordered events

QEMU observes every path event synchronously, at exact chokepoints, on the vCPU thread: sync-fault entry (`cpu_plugin_fault_push`, include/hw/core/cpu.h:728-739, called from all four targets' `do_interrupt`), exception return with an exact LIFO match (`cpu_plugin_fault_pop`, cpu.h:741-761), async-IRQ entry (the same four delivery sites set `plugin_in_async_int` + departure PC, cpu.h:605-606), and async-window close (departure-PC compare in the fetch loop, accel/tcg/cpu-exec.c:2104-2107). All are already spec-mode-suppressed at source (cpu.h:730,743).

But delivery to the plugin is **accumulated state**: monotonic seqs + a depth + one boolean (cpu.h:637-642; `qemu_plugin_get_fault_state`). The plugin edge-detects at the next TB boundary (`fault_tracker_update`, contrib/plugins/champsim_tracer/champsim_tracer.cc:471-517) and the code itself documents the information loss: *"Under a dense fault storm several entries collapse into one observation"* (champsim_tracer.cc:492-496) — `g_fault_entered_resume_pc` (:271) holds exactly one entry per step and fault *returns* are invisible except as depth decrements. Every reconstruction heuristic is compensation for that loss:

- the 3-case fault-merge ladder (:2557-2644) and the frame stack keyed by guessed identity `(asid, resume_pc)` with ASID-drift fallback (`merge_idx_for_resume`, :329-350) and byte-content guards (`tmpl_subrun_pos` / `merge_suffix_matches`, :375-428 — added after a foreign frame at resume `0x4003f0` swallowed the workload's just-sealed block, comment :414-423);
- completion by scanning sealed BBs against frames (`merge_idx_for_completion`, :434-457) instead of knowing the return happened;
- the async stuck-flag repair and the "ORDER MATTERS" gate-ordering contract (:2396-2422).

**Bug families caused:** battle scars (1) fault merge, (2) async exclusion, (3) gate ordering; #86/#87/#88 manifestations; the stale-prev corrupt-frame class (comment :310-316); case-(c) i-fetch-drop hazard (:2578-2586).

### P2. The one legitimate deferral has no owner

TB N's branch outcome and tail-insn post-exec registers are genuinely knowable only at TB N+1 (`current_pc` is the next TB's inline store, champsim_tracer.cc:3747-3748, read at :2508; `snap_prev_tail_dsts` :1822-1870). That 1-entry deferral is irreducible — but instead of being encapsulated, its cursor `g_cp_prev_tb_template` (:186) is a TLS global mutated/read from at least seven sites (async bail :2389-2393, foreign-ASID null :2429, segment-open null :2478, merge ladder :2557-2644, simpoint close :2788, `flush_pending_final_body_entry` :1409, the pivot :2437-2438), each with a position-in-function ordering contract. Pure deferral tax that exists only because of this: the two-stage depth pipeline `g_fault_depth_next → g_emit_fault_depth` (:260-265, stamped at :2552-2553), the `prev_ft==0` boundary case (:2513), and `flush_pending_final_body_entry` (:1393-1468) — a hand-rolled duplicate of the fragment walk *and* of the delay-slot tail-snap logic (:1414-1443 duplicates :1822-1870).

**Bug families:** scar (3) directly; the #90 vclock-freeze re-exposed block drop; the segment-open one-TB loss (:2477-2492); every "prev is stale" merge corruption.

### P3. Capture gating and boundary resets are smeared across the codebase

The async-exclusion decision is re-tested via cross-DSO `qemu_plugin_in_async_int()` calls in five hot capture paths (champsim_tracer_mem_access_recorder.cc:103 and :161, champsim_tracer.cc:837, :929, :2415) instead of at one choke point. Segment-open/flush cleanup is scattered: :2477-2492 (in-gate resets), `reset_segment_local_state` (:1026-1064), `vcpu_tb_flush` (:3822-3858), plus wp.cc's flush-counter dance. Ordering between these fragments is enforced by nothing but code position — the exact soil of scar (3) and of #78 (attribution leak).

### P4. Template lifetime: three regimes, ~12 cross-reference kinds, cleanup by convention

`tb_templates_` is flush-persistent-by-never-freeing (champsim_tracer_bb_template_cache.h:168-186) **except** the #91 bolt-on: `spec_born`/`cp_executed` promotion stamped in `vcpu_tb_exec` (:2305-2307) and a reclaim that performs manual set-arithmetic surgery on `tb_chain_dedup_` (bb_template_cache.cc:740-787), triggered by an uncommitted **`TEST: 256KB`** threshold (champsim_tracer.cc:3809). `bb_map_` is segment-scoped, and `clear_bb_map` must walk *all* translations to null two back-edges (`parent_true_bb`, `rep_subtmpl`) or the next segment derefs freed memory (bb_template_cache.cc:79-84). Dangling-pointer defense is by remembered convention (segment-generation stamps, find-revalidation) rather than by construction.

**Bug families:** scar (4)/#91 spec-born runaway; #90 poison false-drop (spec/CP read-write asymmetry in `detect_tb_poison`); the merge-frame orphan drops (:1050-1062).

### P5. The dominant data structure is ~27× oversized and duplicated per commit

`sizeof(InsnFields) == 3272 B` — six fixed 64-slot `uint64_t` mask arrays (champsim_tracer_mnemonics.h:169-170, :184-185, :229-230) plus `src_regs[64]`/`dst_regs[64]` (:118-119) — and `InsnRegNames` adds 1024 B/insn. Every true-BB commit *duplicates* the fragments' copies into `bb_map_` (bb_template_cache.cc:211, :328-344). Result: ~1 GiB heap where ~100 MiB is real; every lifetime bug (P4) becomes an OOM catastrophe (#91's 11 GiB); and one instruction's metadata spans ~52 cache lines in `emit_field_delta_section` — the profiled runtime bottleneck (docs/architecture.rst:167-208 documents how load-bearing that loop's locality is).

**Cross-cutting finding — the docs cannot spec the tangle zone.** architecture.rst:363-364 ("`tb_templates_` is dropped wholesale by `vcpu_tb_flush`") contradicts bb_template_cache.h:168-174; architecture.rst:648 ("byte-memo and poison set are dropped on `vcpu_tb_flush`") contradicts champsim_tracer.cc:3841-3844; architecture.rst:851-857 and the comment at champsim_tracer.cc:2288-2294 describe a non-recursive `GMutex` while `exec_lock` is a `GRecMutex` (`g_rec_mutex_lock`, :2444); concepts.rst:260-261 still says user-mode-only. ASID pin, marker windows, fault merge, async exclusion, and the vclock layer are entirely undocumented. The real spec of the tangle zone is the comments at champsim_tracer.cc:285-457 and :2374-2431.

---

## 2. Target architecture

### Module map

| # | Module | TU / location | Owned state | Core invariants |
|---|--------|---------------|-------------|-----------------|
| M1 | **Event queue** (QEMU boundary) | `include/hw/core/cpu.h` (+ `plugins/api.c`, `include/qemu/qemu-plugin.h`) | `QemuPluginCpuEventQueue` in `CPUState` (grow-only buf, `len`, `cap`, `enabled`); events `{kind ∈ FAULT_ENTER, FAULT_RETURN, ASYNC_ENTER, ASYNC_RETURN; depth-after; pc; asid; priv}` | Single producer + single consumer = the owning vCPU thread; **grow, never drop**; spec-mode suppressed at source; `asid`/`priv` stamped **at the event instant** (kills ASID drift at the root); drained at every CP `vcpu_tb_exec` *before* any early return |
| M2 | **PathBuilder** | new `champsim_tracer_path_builder.{h,cc}` | `frames_` (base `CtxFrame` + one per in-flight fault: identity from the FAULT_ENTER event + frozen `susp_prev/susp_chain/susp_mem/susp_snaps/anchors/full_tmpl`); **the** single pending-seal slot `prev_tb_`; the `BBChainAssembler` instance; `async_excluding_`; `base_depth_` | (i) exactly one pending-seal TB per frame; (ii) `frames_` mirrors the suffix of QEMU's fault stack for the enabled window (replayed depth == event depth, checked per drain); (iii) every drained event is applied *in order* before the TB is processed; (iv) exactly one live accumulator sink (live path / top frame / muted) |
| M3 | **Capture router** | one TLS state consulted by `MemAccessRecorder::record`/`record_synthetic_load`, reg-snap and synth-EA callbacks | `g_capture_sink ∈ {LIVE, MUTED}` (set only by PathBuilder) | Replaces five independent `qemu_plugin_in_async_int()` tests with one TLS bool; exclusion semantics decided in exactly one module |
| M4 | **TemplateStore** (evolved `BBTemplateCache`) | `champsim_tracer_bb_template_cache.{h,cc}` | `frags_` (CODE+SPEC), `chain_index_` (CODE only), `bb_map_` (SEGMENT), `flush_epoch_`, `segment_gen_`, registered `ReferenceRoot`s | `TmplLife{CODE,SPEC,SEGMENT}` replaces `spec_born`/`cp_executed`; `promote()` is the **only** SPEC→CODE transition and the only chain-index inserter (SPEC unindexed ⇒ reclaim = partition, no index surgery); a CODE template never references SPEC; cross-class pointers are generation-stamped `SegRef` handles (staleness detected at deref, not prevented by remembered walks); `on_tb_flush()` / `on_segment_end()` / `on_segment_open()` are the *only* boundary functions, notifying roots in one explicitly-ordered list |
| M5 | **InsnFields pool** | `champsim_tracer_mnemonics.h` + pack functions in bb_template_cache.cc | 120 B `InsnFields` core with pointer spans; per-template `fields_pool` (one allocation); shared read-only `g_zero_masks/g_zero_regs`; TLS `InsnFieldsScratch` for build | Post-commit immutable; spans sized from final counts/flags; `f->dst_dep_mask[d]` syntax unchanged for every reader/writer and the auto-generated `mnemonics_<isa>.h` refiners; unused spans alias the shared zero arrays (bit-identical to today's `g_new0` read-as-zero) |
| M6 | **Emission** | `champsim_tracer_output.cc`, writer, segment manager | unchanged | `emit_body_entry` + REP fan-out + per-thread `FieldStateTable` + IFRAME discipline untouched; consumes `SealedBB{bb, branch_pc, next_pc, wrong_target, fault_depth, fault_anchors, prefix_mem, prefix_snaps}` |
| M7 | **WP simulator** + (later) **WpScheduler** | `champsim_tracer_wp.cc` (+ small new TU for #92) | unchanged excursion-local state; #92 adds a deferred-excursion retry queue | Kick timing unchanged (synchronous, under `exec_lock`, at each seal — emit_finalized_bb, champsim_tracer.cc:1767-1809); the `g_wp_state.last_executed_tb` handshake (:2295-2298, wp.cc:113-185) stays verbatim |
| M8 | **Window/marker manager** | `tw_manage_window` + marker callbacks | unchanged | Segment/simpoint/marker semantics identical; all resets route through M4's `on_segment_open` |
| M9 | **Time/transparency layer** | `VClockPauseGuard` (champsim_tracer.cc:2268-2273) + cpu-exec.c vclock/spec-vtime/timer-resync/TSC-pin | unchanged | "Resync only at true excursion exit", "never re-enable a clock vm_stop owns" — correct, localized, keep |

### The target `vcpu_tb_exec` (~60-80 lines)

WP early-out (unchanged, :2295-2298) → `promote(cur)` (replaces the `cp_executed` stamp) → `VClockPauseGuard` → icount read → **`qemu_plugin_drain_cpu_events()`** → `exec_lock` → `tw_manage_window` → on segment open: `store.on_segment_open()` + `builder.on_segment_open(depth_now)` + enable queue → build `StepIn{cur, prev_start, prev_ft, current_pc, asid, priv, evs, pinned}` and fold the user clock in one place → `builder.step(in, sealed)` → for each `SealedBB`: prepend prefix mem/snaps, `emit_finalized_bb(...)` → deferred window close keyed on `builder.has_active_chain()`.

Each battle scar becomes one state-machine arrow instead of a gate: `ASYNC_ENTER/RETURN` bracket a mute window (prev untouched ⇒ the :2389-2393 invariant becomes a triviality; no gate ordering exists to get wrong); `FAULT_ENTER` classifies against the **top frame** and `prev_tb_` only (old cases a/b/c, no stack scan, no drift fallback); `FAULT_RETURN` completes by **LIFO position + event**, with the byte-compare retained as a debug assert rather than a matcher; the foreign-ASID drop becomes suspend-or-seal-exactly (legacy drop behind a flag for A/B). The single surviving heuristic — abandoned windows/frames from signal delivery or killed tasks — is confined to one named function, `PathBuilder::repair_abandoned` (parity with :2404-2422 and the orphan drop :1050-1062). The in-flight #83 toggles (`trace-faults`/`trace-interrupts`) become flag-conditional arrows in this one machine rather than new gates.

### Explicitly untouched (the clean parts, preserved as-is)

Output/wire layer (zero recent bugs; largest TU); WP walker internals post-M2; scoreboard inline-op design + inter-segment fast path (budget cond_cb ordering, :3777-3798) minus two dead slots; vclock/transparency layer; `split_tb_into_fragments` + `BBChainAssembler` core + `TbTerminus` model; poison-detector semantics; marker detection; stats registry/graveyard; multi-vCPU interleaving through `exec_lock`; REP fan-out; per-thread regfile/`FieldStateTable` semantics.

---

## 3. Phased migration plan

**Standard gate (G0), required by every phase:** (1) `golden_net.py check` byte-identity against *fixed* pre-captured traces (never re-traced), user-mode 4 ISAs, full-feature flag matrix, `setarch -R`; (2) `python -m champsim_tracer_validator all --isa {x86_64,aarch64,riscv64,mipsel} --run` errors=0 including the flush-stress suite; (3) where system-mode behavior is touched: the #84 capped baseline per ISA **plus a mipsel ×24-run system batch** (the stochastic-bug detector that caught the poison leak and #88); (4) run dirs under `/mnt/md0/QEMU/cst_runs`, 16 GiB + timeout caps. **Perf gate (G1)** for hot-path phases: full-feature mcf 20M ≤ committed baseline (#31 method). Each phase is a standalone commit series that leaves the tree green; each phase updates the doc sections it touches (documentarian voice — describe the model, not the change).

### Phase A — Baseline lock-down (no product code)
Reconcile the working tree so later A/B comparisons are clean: land-or-shelve the uncommitted #77 diagnostics (`cst_ring_push` at champsim_tracer.cc:2441 and its ring), decide the `TEST: 256KB` threshold at :3809 (restore the intended budget or carry to Phase B), and clear stray files (`test.txt`, `gcc_aarch64_all_20M.cst`, `wp_leak_audit.md`, `issue77_session_findings.md`) out of the plugin directory. Re-capture goldens (`golden_net.py capture`), record `CST_MEMSTATS` + massif on the #91 mipsel workload, and the mcf 20M perf table.
**Gate:** G0 full. **LOC:** ~0 product; ~200 diff lines resolved.

### Phase B — InsnFields + InsnRegNames diet (in-memory only; land first)
The pointer-member trick makes the whole tree diff-free: `InsnFields` keeps every member *name* but the six mask arrays and two reg arrays become pointer spans into a per-template `fields_pool` (fat `InsnFieldsScratch` during build; one `g_new` per template at commit; empty spans alias shared `static const` zero arrays reproducing today's `g_new0` read-as-zero bit-for-bit). Sub-steps, each gated: **B1** core diet + `insn_fields_pool_size`/`insn_fields_pack` wired into `create_tb_template`, `build_bb_template`, `commit_true_bb_refs` (delete `gather_fields`), `ensure_rep_subtmpl`, the deleter, `mem_stats`, the spec-byte estimator; **B2** same recipe for `InsnRegNames` (1024 → ~24 B/insn); **B3** recalibrate the proactive-flush budget (~25× down or convert to template count) so reclaim cadence is preserved — its own commit, because a golden diff here is a *pre-existing* flush-invariance bug surfacing, which is signal.
3272+1024 → ~200 B/insn (~21×): the ~1 GiB healthy heap drops to ~60-120 MiB, #91-class runaways scale identically, and `emit_field_delta_section` reads 2-3 cache lines per insn instead of 52. The generated `mnemonics_<isa>.h` files are untouched by design.
**Why first:** biggest win, zero ownership/control-flow semantics, independent of everything else, and it makes every later phase's memory diagnostics legible.
**Gate:** G0 + G1 + CST_MEMSTATS/massif delta vs Phase A. **LOC:** ≈ +450 / −250.

### Phase C — Boundary-function consolidation (pure motion)

> **Outcome (2026-07-08): audit-complete; motion largely unnecessary; ReferenceRoot re-scoped into Phase E.**
> The anticipated scatter was mostly eliminated by the earlier M-wave refactors: `vcpu_tb_flush`
> is already the single flush boundary (wp counter + wp cursor + cache reclaim, each line owned),
> and segment-open handling is split **by design**, not by accident: `reset_segment_local_state`
> is the *opener-thread* handler (global caches + own TLS) while the `segment_just_opened` in-gate
> block is the *per-thread* handler — `g_merge_stack` / `g_cp_prev_tb_template` are `thread_local`,
> so every vCPU must clear its own cursors as it crosses into the new segment (roles now documented
> in-code; an attempted merge was reverted before gating — a latent multi-vCPU break that
> single-vCPU gates cannot catch). The same thread-locality argument applies to a cache-owned
> ReferenceRoot notify list: TLS roots can only be reset from their own thread, so root ownership
> moves into PathBuilder (Phase E), which is per-thread by construction.
Add `on_tb_flush()` / `on_segment_end()` / `on_segment_open()` to the template cache and move the scattered boundary code **verbatim** into them (champsim_tracer.cc:2477-2492, :1026-1064, :3822-3858, wp.cc flush hooks). Introduce `ReferenceRoot` registration for every raw-template-pointer holder: `g_cp_prev_tb_template`, the chain assembler, `g_wp_state`, the merge frames, the writer's in-flight body queue. Ordering becomes named sequential statements in one function — the structural fix for the scar-(3) bug class — and creates exactly the seams Phase E plugs into.
**Gate:** G0 (byte-identity everywhere — no behavior change intended). **LOC:** ≈ +150 new / ~300 moved.

### Phase D — QEMU event queue, additive, shadow-validated
Add `QemuPluginCpuEventQueue` + `cpu_plugin_evq_push` (cpu.h, next to fault_push/pop), producers at: `cpu_plugin_fault_push`/`_pop`, a `cpu_plugin_async_enter()` helper at the four delivery sites (target/arm/helper.c:11087-11088 and peers), and the departure-PC clear (cpu-exec.c:2104-2107 → `ASYNC_RETURN`). New API `qemu_plugin_drain_cpu_events` / `qemu_plugin_cpu_events_set`. **Keep** the fault stack, seq counters, `qemu_plugin_get_fault_state`, and `plugin_in_async_int` fully functional. Plugin gains `CST_EVQ_CHECK`: drain each `vcpu_tb_exec` and assert the event replay reproduces the edge-detectors' conclusions (entry edge ⇔ ≥1 FAULT_ENTER; depth == last event depth − base; async transitions bracketed). Divergences are catalogued **found-bugs in the old reconstruction** before any behavior change — and may illuminate #77.
**Gate:** G0 (user mode trivially green — queue empty); system runs with `CST_EVQ_CHECK=1`, divergence catalog reviewed. **LOC:** ≈ +200 QEMU / +150 plugin.

### Phase E — PathBuilder behind `events=1` (legacy default unchanged)
New TU `champsim_tracer_path_builder.{h,cc}` implementing M2 exactly as specified in §2 (CtxFrame = the merge frame *is* the context frame; `step()` = apply events in order → mute check → `repair_abandoned` → `process_tb`, where `process_tb` is today's `collect_finalized_bbs` walk emitting `SealedBB`s). Includes M3 (capture-sink mute) and moves the user-clock fold + `is_system` CP-ground-truth stamp (:2354-2371, verbatim semantics) into the one `StepIn` prologue — also fixing the latent SMP hazard of the plain-static `g_user_icount/g_user_icount_seen` (:213-214) by folding under `exec_lock`. Legacy path untouched and default.
**Gate:** G0 with a hard requirement: user-mode goldens **byte-identical** under `events=1`. System-mode A/B vs legacy via validator invariants + `cst_audit` budgets + `blocks_covered`; every accepted difference must be one of exactly two named improvements (foreign-ASID suspend-vs-drop — legacy drop available behind a flag for byte-parity A/B; per-event multi-fault handling). `CST_BLKWATCH`/`CST_FAULT_DIAG` must work against the new path. **LOC:** ≈ +900 new / +120 glue.

### Phase F — Flip default, delete the reconstruction
Delete from champsim_tracer.cc: `FaultExcursionTracker` + `fault_tracker_update` (:240-258, :471-517), the depth pipeline + `g_fault_entered_resume_pc` (:260-271), `PendingFaultMerge` + `g_merge_stack` + all matchers (:285-457) and the stash/completion blocks (:2556-2745), the async + foreign-ASID gate ladder with its ordering comments (:2374-2431), `g_cp_prev_tb_template` as a global (:186), `flush_pending_final_body_entry` (:1393-1468, replaced by `PathBuilder::flush_final` — deleting the duplicated delay-slot snap), the five per-callback async gates (replaced by the sink bool), and the two dead scoreboard slots (`prev_bb_terminus` arming :3728-3731 + WP save/restore wp.cc:131-132/:162-163; `last_counted_start_pc`). Delete from QEMU: the four seq/pc fields (cpu.h:639-642) and `qemu_plugin_get_fault_state`. Decide + document the shipped foreign-ASID default before this phase.
**Gate:** G0 full (incl. mipsel ×24 system) + G1 (expect neutral-or-better: removes 3 cross-DSO calls/insn + the scan matchers) + a signal-heavy long-run for `repair_abandoned`. **LOC:** ≈ −1100 plugin / −70 QEMU.

### Phase G — Template lifetime classes
`TmplLife{CODE,SPEC,SEGMENT}` replaces `spec_born/cp_executed`; `promote()` promotes whole sibling chains (fixing the head-only stamp) and is the only inserter that can move a chain into the CODE `chain_index_`; SPEC chains live in a separate SPEC-class index dropped wholesale at reclaim — NOT unindexed: spec translations are full multi-insn TBs in the current tree (shared spec-mode code cache), and CP adoption of WP-minted chains is load-bearing (~35% of dedup hits, 37/105 translations in the w1_baseline golden cell; measured in the Phase G g2_stop_evidence dedup logs), so creation-time SPEC visibility is required for template-id byte-identity. `reclaim_spec_templates` still collapses to a partition (plus one O(1) index clear) with no per-chain index surgery or defensive `next_tb_fragment` nulling. `SegRef` generation-stamped handles replace raw `parent_true_bb`/`rep_subtmpl`, deleting the O(all-translations) back-edge walk in `clear_bb_map` (bb_template_cache.cc:79-84). Debug boundary audit: after root notification, assert no root retains a pointer into the reclaimed class. Rename `BBTemplateCache` → `TemplateStore` last.
**Gate:** G0 + flush-stress + REP-heavy x86 (SegRef on the fan-out hot path) + multi-segment SimPoint run + CST_MEMSTATS after forced flush storms + G1. **LOC:** ≈ 400 changed / −150.

### Phase H — Task #92: deferred-WP for un-resident wrong targets — **built on the new shape**
#92 (0-block WP when the wrong-path target page is un-resident) must not be bolted onto the old gates. On the new shape it is a small module, not a new special case: a `WpScheduler` seam between `SealedBB` and `simulate_wrong_path_ext` — when the excursion would 0-block on an un-resident target, enqueue `{branch_pc, wrong_target}` and retry at a later CP visit of the same branch once resident, attaching the chain to *that* visit's body record (the wire already supports per-entry WP chains; no format change). Everything it needs exists by now: the kick point is one call site (M7), any spec templates it mints are `TmplLife::SPEC` so runaway reclaim is already proven (Phase G), residency/fault outcomes are observable without new heuristics (Phase D events + existing spec-fault plumbing), and its lifetime hooks are registered roots (Phase C). Requires its own one-page design review against the pending-task notes before coding.
**Gate:** G0 + a purpose-built validator case (branch whose wrong target is cold-unmapped) + WP-chain-length distribution comparison vs baseline. **LOC:** ≈ +250-400.

### Phase I — Documentation + validator semantics (consolidation)
Rewrite architecture.rst's CP-flow steps (currently :471-523) around the event queue + PathBuilder; add "Event queue and path builder" and "Template store lifetimes" sections; fix the four contradictions from §1 (tb_templates_ flush claim :363-364; poison-on-flush :648; GMutex/two-lock :851-857 and the stale comment at champsim_tracer.cc:2288-2294; concepts.rst:260 user-mode-only); document ASID pin, marker windows, fault merge, async exclusion, vclock layer for the first time; update `docs/qemu_modifications.rst` with the queue; update `validator/champsim_tracer_validator/_system.py` to derive expected depth/merge behavior from event semantics.
**Gate:** `make -C contrib/plugins/champsim_tracer/docs html` clean; validator green. **LOC:** ≈ 500 rst / 150 validator.

**Dependency structure:** A → B → C → D → E → F → G → H → I is the recommended serial order; B is independent of C-F and G(B2/B3-parts) can proceed in parallel with D/E if desired (different files), but never two phases in flight in the same TU. Phases D and E are pure additions revertible by flag; nothing before F changes any shipped behavior.

---

## 4. Non-goals and risk register

### Non-goals (explicit)

1. **No wire-format change.** `CST_MAGIC` stays frozen through pre-release; `fault_depth`/`fault_anchors` and per-entry WP chains already exist in the format. Every phase is gate-checked as in-memory-only.
2. **No rewrite of the clean subsystems** (§2 "untouched" list). In particular the WP walker's interface `(branch_pc, correct_target, wrong_target) → chain-by-value` and the scoreboard inline-op design are load-bearing and correct.
3. **No ASID/context-switch event kind.** MMU-context register writes are noisy (handlers rewrite MIPS `EntryHi` mid-excursion — the origin of the drift heuristic); ASID/priv remain *attributes sampled per event and per TB*, not ordered events. The gate-ordering bug class dies via the event-driven async window, not via an ASID event.
4. **No elimination of the 1-entry deferral or the post-TB register capture.** Branch resolution genuinely needs the next TB; tail-insn post-exec values genuinely need a post-TB hook. The plan encapsulates the deferral in one owner; it does not pretend to remove physics.
5. **No insn-pool sharing between fragment and true-BB templates.** Copy semantics keep the SPEC-reclaim and SEGMENT-drop proofs independent; ~2× more savings is not worth coupling them at a ~100 MiB post-diet footprint.
6. **Out of scope:** #77's riscv64 residual (Phase D's shadow check may illuminate it, but it is its own investigation); SMP marker-mode support beyond fixing the `g_user_icount` thread-safety hazard; upstreaming the QEMU hooks; new ISAs.

### Risk register (top 5)

| # | Risk | Mitigation |
|---|------|------------|
| R1 | **Uninstrumented target exception path** → missing event → PathBuilder seals a faulting BB against the vector (phantom edge), the pre-#72 failure mode reborn. | Keep QEMU's `plugin_fault_depth` and cross-check replayed depth per drain (one compare, warn-once). Phase D's `CST_EVQ_CHECK` catalogues every divergence *before* any behavior change. The four ISAs' chokepoints are already verified (#71). |
| R2 | **System-mode behavior deltas** (foreign-ASID suspend-vs-drop; per-event multi-fault) break a consumer assumption or hide a regression inside an "improvement". | Legacy drop selectable by flag for byte-parity A/B; accepted-diff whitelist limited to the two named improvements; shipped default decided and documented before Phase F; mipsel ×24 batches for the stochastic classes. |
| R3 | **Perf regression on hot paths** (per-TB drain; SegRef compare on REP fan-out; pack cost at build; the architecture.rst:167-208 micro-opts are load-bearing). | G1 (mcf 20M) on B/E/F/G. Expected net positive: diet densifies the emit loop 52→2-3 lines/insn; F removes three cross-DSO calls per instrumented insn and the scan matchers. Fallbacks: cache the SegRef deref per finalized chain; drain is one call per TB against a same-thread buffer. |
| R4 | **Pointer-lifetime regressions during transition** — `InsnFieldsScratch` copied by value (carries source-array pointers); a root retaining a template pointer across a boundary; SegRef misuse. | Scratch non-copyable + grep audit (only pack sites may copy); shared zero-spans reproduce read-as-zero for any missed flag guard; debug boundary-audit asserts after root notification; ASAN runs per the plugin-lifetimes rule; golden identity at every step. |
| R5 | **Abandoned frames remain heuristic** (signal delivery ERETs to the handler, not the faulting PC; killed tasks) — cannot be eliminated, only confined. | All repair logic in one named `repair_abandoned` (prune on pinned-user arrival, parity with today); QEMU stack capped at 64 (cpu.h:636); an explicit signal-heavy long-run test added to the Phase F gate and kept in the validator. |

**Bottom line.** The five root problems have three orthogonal fixes — deliver causality as data (D-F), give path state one owner (E), give templates one owner with declared lifetimes (C, G) — plus a data-shape diet (B) that pays for the whole effort in memory and hot-loop locality before any semantics change. Roughly −1,100 lines of proxy-inference and merge heuristics are replaced by ~900 lines of an explicit state machine whose invariants are assertable, every battle scar maps to a single labeled transition instead of a positional gate, and #92 lands as a module on the new seams instead of the next scar.