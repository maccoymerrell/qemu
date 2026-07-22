# Fault / Merge / WP-Machinery Rearchitecture — Design Plan

**Prepared for:** Maccoy Merrell (sole maintainer). **Status: IMPLEMENTED
2026-07-22 — stages 0–5 landed on `champsim-trace` (NOT pushed).** All paths
relative to `/mnt/md0/QEMU/qemu`; the plan below is preserved as the design of
record and annotated where the implementation refined it.

### Implementation status (stages 0–5 landed)

| Stage | Content | Byte class | Result |
|---|---|---|---|
| 0 | Baseline lock: retire-at-return primitive (byte-inert pieces); `complete_merge` deeper flush deferred | inert | goldens byte-identical; baseline contention rate recorded |
| 1 | WP-walker decomposition (`WpWalkState`/`WpStep`, full driver switch) | inert everywhere | 8/8 golden-gated extractions byte-identical |
| 2 | Per-`(thread,asid)` frame identity into completion; byte guard → diagnostic | inert single-process | goldens byte-identical; 2-process A/B clean |
| 3 | Suspend-or-seal, **foreign-ASID** arrow (`SuspendedPrev`/`susp_stack_`, resume arrow, `SUSPENDED_FOREIGN`, `complete_merge` anchor guard) | byte-affecting system multi-process (the fix) | contention JUMP=0 ANCHOR=0; A/B confirms the named improvement |
| 4 | Suspend-or-seal, **abandoned-async** arrow (same machinery + one-step resume hold-off) | inert off async-recovery path | goldens byte-identical; 30-seed wave JUMP=0 ANCHOR=0; arm not exercised (see below) |
| 5 | Docs (`architecture.rst` suspend-or-seal section) + validator-semantics confirmation | non-wire | docs build clean; validator green; goldens byte-identical |

**Gate summary (per stage):** both golden nets byte-identical (user 4-ISA +
`--system` CP-user-slice); `validator full` green (pass=24 fail=0 xfail=1
non-gating, mutation 15/15, `syscall_fault_nesting` info=1); the tight-island
contention matrix (2× 4-core islands, `-j12` = 3× oversub) at
**depth-JUMP = 0 AND anchor-at-unwind = 0** post-arc, against a recorded
non-zero pre-arc baseline.

**Two load-bearing findings (recorded so they are not re-litigated):**

1. **Resume keys on `pin_effective_asid` ONLY, not the live ASID.** A kept
   kernel block's live address-space register is a PTI/TLB overlay, not
   ownership (observed `asid=0x2480000` vs `live=0x18c0000`); a live-ASID
   resume gate stranded the pinned process's own depth-1 kernel-handler
   suspensions. Cross-process safety at *completion* keys user frames on the
   hard asid and kernel frames on content — that is the completion path's
   job, not the resume re-arm's.
2. **The `complete_merge` anchor guard is required alongside suspend-or-seal.**
   Suspend-or-seal closes the depth-JUMP class (a dropped pinned depth-1
   handler; manifestations 2/3). The residual ANCHOR-at-depth-0 came from a
   *foreign* task's fault frame completed via the kernel-content path with no
   traced pinned excursion; the guard emits it as a plain block clamped to the
   predecessor depth (no anchor, no jump). Both are needed for the 0/0 gate;
   both are byte-inert off the contention path.

**Stage-4 refinement of §1.2 (recorded).** The plan's "same substitution" for
the abandoned-async arm is correct in machinery but needed one guard the plan
did not scope: the foreign arm *returns* (its suspension defers to a later
step), whereas the abandoned arm *falls through* to promote the current TB, so
a bare substitution would let the same step's resume arrow immediately seal the
just-suspended prev against that TB — the cross-thread taken edge the
departure-PC override exists to prevent. A one-step resume hold-off defers the
suspension to prev's true successor. The abandoned arm did **not** fire in the
churn harness (`susp_abandoned = 0` across 15 harvested seeds while the foreign
arm fired 26× balanced): its trigger — an async window latched from live state
before the segment's first prime, with a non-null deferred prev — is a
startup/segment-boundary race the marker-window workload does not reproduce and
that cannot be forced deterministically from userspace. It is documented as
structurally-identical-to-proven (identical `suspend_prev`/`resume_suspension`,
guard byte-inert off-path per the byte-identical goldens).

## 0. DECISIONS LOCKED (§5 detail below)

- **A — STACK of suspensions** (maintainer chose the stack over the
  recommended single-slot): nested foreign/async spans each push a suspension;
  a resume pops the matching `(thread,asid)` entry; NO displacement loss. §1/§3
  storage becomes a bounded stack (orphan-drop each entry at `on_segment_open`
  and stale-sweep per the rules `frames_` already follows); cap it (few
  concurrent nested spans) with retire-at-return as the over-cap tail.
- **B — FULL WP-walker decomposition** (`WpWalkState` + `WpStep` enum, ~40-line
  driver switch; the Phase-H `WpScheduler`/#92 seam), staged so each extraction
  is independently golden-gated.
- **C — UNIFY frame identity** with the existing `pin_effective_asid` /
  `CtxFrame::asid` (`46bbff4a2a`) machinery; the resume-PC+bytes byte guard
  demotes to a pure diagnostic.
- **D — SHIP suspend as default**, legacy-drop behind `CST_FOREIGN_DROP` for
  byte-parity A/B; remove the flag once the contention gate is 0-fail over two
  independent 50-seed waves.
- **E — retire-at-return PERMANENT backstop** (covers the structurally
  un-resumable cases the stack can't: killed task, orphan, over-cap, a foreign
  span that never returns; its anchor guard bars any depth-JUMP→anchor trade). Everything cited was read in the current tree, not assumed. The
wire format and `CST_MAGIC` are untouched by every stage.

This is the **fault-machinery-correctness capstone** of the broader
`rearch_plan.md` (§7 reconciles): the event queue (M1/Phase D), the PathBuilder
(M2/Phase E) and the capture-mute sink (M3) are all landed and shipped. Two
items remain that `rearch_plan.md` named but deferred, and that two targeted-patch
attempts escalated because they are structural, not local:

1. **`syscall_fault_nesting` sub-type (b)** — a nested-fault-unwind
   depth-attribution bug that survives the retire-at-return patch, because its
   two live manifestations lose the intermediate handler block to a *drop*, not
   to a leak. The fix is the **suspend-or-seal** arrow the PathBuilder header
   already reserves fields for (`champsim_tracer_path_builder.h:113-119`) and
   the drop arm already flags (`champsim_tracer_path_builder.cc:898`, *"rearch:
   suspend-or-seal candidate"*).
2. **WP-walker decomposition** — `simulate_wrong_path_ext`
   (`champsim_tracer_wp.cc:294-1281`, ~988 lines) is one monolithic `while`
   loop sharing a `WpAccum` plus ~20 loop-carried locals steered by
   `continue`/`break`. The refactor pass dropped it as byte-risky without a
   status-enum-return + shared-state-struct design; it is a prerequisite for
   `rearch_plan.md` Phase H (the `WpScheduler` seam for task #92).

---

## 0. Problem statement — the three manifestations and the two dropped levels

The oracle (`validator/champsim_tracer_validator/validator.py:5063-5223`,
mirrored by `/mnt/md0/QEMU/cst_runs/faultflake/check_violations.py`) asserts two
things over consecutive **same-tid** body entries:

- **depth-JUMP:** `abs(d - pd) > 1` is an error (`validator.py:5161`) — a
  fault stack steps one level at a time.
- **anchor-at-unwind:** a fault-anchored (whole-BB-merged) entry whose same-tid
  predecessor is not strictly deeper (`fault_anchors and pd <= d`,
  `validator.py:5177-5185`) is an error — a merged faulting BB must land at the
  unwind of its excursion.

Both reduce to the same wire requirement: **every fault level between two
adjacent depths must have at least one emitted block at that level.** The bug is
that the intermediate (depth-1) handler block is silently lost, so the wire
steps `2 -> 0` (or `0 -> 2`).

The three evidence-confirmed manifestations:

| # | Name | Locus | Fixed by |
|---|------|-------|----------|
| 1 | leaked-inner-frame unwind `2 -> 0` | the inner frame's resume suffix is the deferred prev a drop arm clears; the frame lingers un-returned until the coarse user-privilege stale-frame sweep (`champsim_tracer_path_builder.cc:1155-1178`, commit `483e93d625`) collapses the whole stack to 0 | **retire-at-return** — preserved patch `/mnt/md0/QEMU/cst_runs/faultflake/faultb_attempt_FINAL.patch` (`flush_dropped_prev` / `flush_frame_unwound` / `g_last_emit_fault_depth` anchor guard) |
| 2 | foreign-dropped **handler blocks** -> anchored merge at depth 0, no frame to retire | the depth-1 handler's own blocks are `DROPPED_FOREIGN` (`champsim_tracer_path_builder.cc:897-926`) across a foreign-ASID span, so no frame ever forms at depth 1 and there is nothing to retire | **suspend-or-seal** (this plan §1) |
| 3 | entry-side rapid-nest `0 -> 2` | the symmetric entry case: the depth-1 handler block sits on the deferred-prev slot when a foreign/async drop clears it, so only the depth-0 user block and the depth-2 nested handler emit | **suspend-or-seal** (this plan §1) |

**Manifestation 2, confirmed in-tree.** `analyze_fail.py` on the post-retire-fix
trace `/mnt/md0/QEMU/cst_runs/faultflake/FAILP_s4151/s4151_x86_64.cst`
(`churn_test --system --isa x86_64`, tight-island contention) shows tid 0
running sustained `depth=2` kernel handler blocks
(`pc=0xffffffffae60...`, seqs 5439-5444), then a single
`depth=0 anch=[1]` **merged** entry (`pc=0xffffffffae49d331`, seq 5445): the
depth-1 level never reached the wire, so the wire steps `2 -> 0`. Post-fix
batches still fail 3/64 seeds (`postfix2xB`) — the retire-at-return patch fixes
manifestation 1 but **cannot** fix 2/3: there is no in-flight depth-1 frame to
retire because the handler's own blocks were dropped, not merely un-returned.

The common cause is the same drop the PathBuilder header already calls out
(`champsim_tracer_path_builder.h:113-119`): the foreign-ASID boundary
**DROPS** the deferred prev (`clear_prev`, `champsim_tracer_path_builder.cc:913-925`)
and the abandoned-async-window recovery drops it too
(`champsim_tracer_path_builder.cc:837-841`). When that dropped block *is* the
intermediate handler level, its level vanishes. **Suspend it instead of
dropping it**, and the level survives the foreign/async span and seals when the
pinned context returns.

---

## 1. Suspend-or-seal

### 1.1 The state a suspension freezes

The deferred-prev "context" the seal phase consumes is spread across four
thread-local sinks. A suspension must freeze all four atomically (they are the
same four a `CtxFrame` already stashes for a fault excursion —
`champsim_tracer_path_builder.h:120-129`):

| Frozen field | Live source today | Why it must freeze |
|---|---|---|
| `susp_prev` (`BBTemplate *`) + `susp_depth` (`uint32_t`) | `prev_tb_` / `prev_depth_` (`champsim_tracer_path_builder.cc:934-935`) | the block whose seal emits the intermediate level and completes its merge |
| `susp_mem` (`std::vector<WPMemAccess>`) | the CP memop accumulator, drained via `g_mem_recorder.take_cp` (`champsim_tracer_mem_access_recorder.h:43`) | prev's committed memops; left in the live buffer they collapse onto the next emitted entry's insn 0 (the exact leak the drop arm's `clear_cp` closes, `champsim_tracer_path_builder.cc:913`) |
| `susp_snaps` (`std::vector<RegSnap>`) | `pending_reg_snaps` (`champsim_tracer_path_builder.h:104`) | prev's already-captured per-insn dst snaps; left live they prepend to the next entry and slide positional reg-data attribution (`champsim_tracer_path_builder.cc:914-922`) |
| `susp_chain` (the in-flight `g_cp_chain` prefix) | `g_cp_chain` fragments (`champsim_tracer_bb_chain_assembler.h:84`) | when prev is mid-true-BB (a page-split BB spanning TBs), the pre-prev fragments live in the chain assembler; a resume must continue that BB, not restart it |

`g_cp_chain` today has no save/restore (`champsim_tracer_bb_chain_assembler.h:74-84`,
copy/assign deleted). The suspension needs a `BBChainAssembler::detach_state()
-> ChainState` / `attach_state(ChainState&&)` pair (move the five private
members out and back) or an explicit `ChainState` snapshot struct. Between most
steps the chain is empty (the seal finalizes+resets), so `susp_chain` is
usually a no-op; it matters only for the page-split-BB-across-foreign-span
corner, which the design must still hold to stay byte-identical on that path.

Storage: a single `SuspendedPrev susp_` member on `PathBuilder` plus a
`bool susp_active_`. The common case is one foreign (or async) span in flight at
a time. Nested spans before any resume are handled by the displacement policy
(§5, Decision A).

### 1.2 The suspend arrow (replaces the two DROP arms)

Two sites drop the deferred prev today; both become suspend:

- **Foreign-ASID boundary** (`champsim_tracer_path_builder.cc:897-926`). When
  `drop` is decided and `prev_tb_` is non-null, instead of `clear_cp` /
  `pending_reg_snaps.clear()` / `clear_prev()`:
  1. freeze the four fields into `susp_` (take the mem buffer, move the snaps,
     detach the chain, record `prev_tb_`/`prev_depth_`), set `susp_active_`;
  2. `clear_prev()` (the slot is now empty; the suspension holds the block);
  3. `g_capture_mute = true` (the foreign TB's accesses stay excluded, exactly
     as today);
  4. return a distinct status `SUSPENDED_FOREIGN` (or keep `DROPPED_FOREIGN`'s
     glue path — it already unlocks and returns; see §5 Decision D for the A/B
     legacy-drop flag).
  The `kexc` ownership edges (`champsim_tracer_path_builder.cc:872-896`) are
  unchanged: suspension is orthogonal to *which* foreign TBs drop.

- **Abandoned-async-window recovery, no-departure-PC arm**
  (`champsim_tracer_path_builder.cc:837-841`). Same substitution. The
  departure-PC arm (`:834-836`) already preserves prev correctly by sealing
  against the window's departure PC (`seal_pc_override_`), so it is untouched —
  suspension only replaces the `else if (prev_tb_)` **drop**.

The pure-async **SUSPENDED** bail (`champsim_tracer_path_builder.cc:849-860`)
is already correct — it leaves `prev_tb_` untouched, so the resume TB seals prev
against its real target. Suspend-or-seal does **not** touch it; it only converts
the two paths that actively *discard* prev.

### 1.3 The resume arrow

At the top of `step_events` **on a step that will `CONTINUE`** (i.e. survives
the async gate and the foreign-ASID gate — the pinned process is back at an
owned, non-excluded TB), before the promote at
`champsim_tracer_path_builder.cc:929-936`:

```
if (susp_active_ && this_tb_resumes_pinned_context) {
    prev_tb_    = susp_.prev;            // re-arm the pending-seal slot
    prev_depth_ = susp_.depth;
    g_mem_recorder.prepend_cp(susp_.mem);          // restore committed memops
    pending_reg_snaps.insert(begin, susp_.snaps);  // restore per-insn snaps
    g_cp_chain.attach_state(std::move(susp_.chain));
    susp_active_ = false;
}
// ... then the normal promote: walk_prev_ = prev_tb_; set_prev(in.cur);
```

Now `cur` (the pinned resume TB) is prev's true architectural successor: the
seal phase walks the restored suspended prev against `cur`'s start_pc, emits the
intermediate handler block **at its own depth** (`prev_depth_` ->
`walk_depth_` -> `g_emit_fault_depth`, `champsim_tracer_path_builder.cc:1222-1225`),
and `frame_idx_for_completion` (§2) matches its frame — completing the depth-1
merge at depth 1. The wire steps `2 -> 1 -> 0` (manifestation 2) and
`0 -> 1 -> 2` (manifestation 3). Off the contention path — user mode and a
deterministic single-process system trace take **no** foreign drops — no
suspension ever forms and the output is byte-identical.

**`this_tb_resumes_pinned_context`** is the resume predicate. The suspended prev
belongs to the pinned process (foreign TBs never seed one — they are the span
being suspended *across*). A TB "resumes" it when the step reaches the promote
with the pinned process owning `cur`: user-owned priv-0, or a kept kernel TB
under `kexc` (`champsim_tracer_path_builder.cc:872-896` already computed
`drop==false` to reach the promote). So the predicate is simply *"we reached the
promote with a live suspension"* — no new classification. The one nuance is a
**cross-context resume**: if the suspended block's asid differs from the
resuming TB's asid, the block did not resume — see §2 and Decision A.

### 1.4 Retire-at-return integration (the backstop, manifestation 1)

Suspend-or-seal covers the case where the pinned context **returns and reseals**.
Retire-at-return (the preserved patch) covers the residual case where the block
**cannot** reseal: a frame whose `FAULT_RETURN` was suppressed non-LIFO and
whose resume suffix never seals, a killed task, or a suspension **displaced** by
a second foreign span before it could resume (Decision A). The two are
**complementary**, not redundant:

- Land the preserved patch (`flush_dropped_prev` + the `complete_merge` deeper-
  frame backstop + the `g_last_emit_fault_depth` anchor guard,
  `faultb_attempt_FINAL.patch`) as the retire-at-return primitive.
  **Stage 0 landed only the byte-inert, hazard-free pieces** — `flush_dropped_prev`
  (the two DROP-arm retire calls), `flush_frame_unwound`, and the
  `g_last_emit_fault_depth` anchor guard. The **`complete_merge` deeper-frame
  flush is DEFERRED** (a `TODO(stage2/3)` marks its site in
  `champsim_tracer_path_builder.cc`): it unconditionally flushes every frame
  nesting deeper than the one completing, and the frame it reaches is picked by
  `frame_idx_for_completion`'s resume-PC+bytes byte guard, which is
  cross-process-ambiguous for shared kernel code — an errant flush there could
  erase another process's live excursion. It becomes safe only once Stage 2
  unifies frame identity on `(thread,asid)` (Decision C), and lands then
  alongside the suspend-or-seal arrow. `flush_dropped_prev` carries no such
  hazard: it fires on a DROP arm where `prev_tb_` is the *pinned* process's own
  block (the foreign TB has seeded no frame), so its `frame_idx_for_completion`
  match is within one process.
- Under suspend-or-seal, `flush_dropped_prev` fires only when a suspension is
  **discarded without resuming** (segment orphan-drop; displacement;
  stale-frame sweep while a suspension is held) — it becomes the "suspend
  couldn't cover this" tail, not the primary path. Its anchor guard
  (`g_last_emit_fault_depth > f.depth`) still guarantees the retire can never
  trade a depth-JUMP for an anchor-at-unwind violation.

Decision E (§5) locks whether retire-at-return stays a permanent backstop or is
re-scoped once suspend-or-seal is proven to cover 2/3.

---

## 2. Per-`(thread,asid)` frame identity

`PathBuilder` is already per-thread by construction (TLS,
`champsim_tracer_path_builder.cc:59-63`), so the **thread** dimension of frame
identity is implicit. The **asid** dimension is where completion is still
process-ambiguous:

- `frame_idx_for_resume` (`champsim_tracer_path_builder.cc:455-464`) and
  `frame_idx_for_block` (`:476-489`) **already** key on `frames_[i].asid == asid`
  (the guard the keying work `46bbff4a2a` added), because a `FAULT_ENTER`/
  `FAULT_RETURN` event carries `ev.asid` stamped at the fault instant
  (`include/qemu/qemu-plugin.h:1650`).
- `frame_idx_for_completion` (`champsim_tracer_path_builder.cc:502-544`) does
  **not** — it keys on `resume_pc == suffix->start_pc` plus the byte-content
  guard `merge_suffix_matches` (`:137-141`), because the completing object is a
  *just-sealed BB* (`PendingEmit`), which carries no asid. Owned processes share
  load VAs (`:87-99`), so on a fixed-width ISA two processes' code at the same VA
  yields identical PCs, sizes **and bytes** — the byte guard is the only
  discriminator today, and it is a heuristic, not identity.

**Design:** thread the seal-time asid into completion so it is a hard key, not a
content guess:

1. The seal phase runs on the pinned process's live context. Stamp the seal's
   effective asid — the same `in.pinned_asid` the glue already samples
   (`champsim_tracer.cc:4154`, `pin_effective_asid`) — into a new
   `step_seal` local, and pass it to `frame_idx_for_completion(suffix, seal_asid)`.
2. `frame_idx_for_completion` requires `frames_[i].asid == seal_asid`
   **first**, then `resume_pc == suffix->start_pc`, then keeps
   `merge_suffix_matches` demoted to the debug assert the header comment already
   wanted (`:517-534`) — the asid key makes the cross-ASID swallow the byte
   guard was added to catch (frame stashed at resume `0x4003f0` by another
   process, `:130-136`) **impossible by construction**, so the byte compare is
   no longer load-bearing for correctness, only a diagnostic.
3. Suspend/resume matching (§1.3 `this_tb_resumes_pinned_context`) uses the same
   key: a suspension records the owning asid (`susp_.asid = in.pinned_asid` at
   suspend time), and a resume requires the resuming TB's effective asid to
   match. A different-asid TB reaching the promote does **not** resume the
   suspension (it stays held for its true owner, or is displaced per Decision A).

This is **byte-identical in single-process** (one asid, so the asid predicate is
always true and completion behaves exactly as the byte guard did — the header
already asserts the byte check "always held where the old assert did",
`:522-524`). It changes only cross-process completion, which is precisely the
system-multi-process regime the contention matrix exercises.

Decision C (§5) locks whether this unifies with the existing `kexc`/asid
machinery (reuse `pin_effective_asid` + `CtxFrame::asid`) or introduces a
parallel key.

---

## 3. WP-walker decomposition

`simulate_wrong_path_ext` (`champsim_tracer_wp.cc:294-1281`) is ~988 lines: an
outer `while` (`:415`) over a `WpAccum` (`:43-106`) plus ~20 loop-carried locals
(`sim_insns`, `early_exit`, `fault_stop`, `last_fault_pc`, `repeated_fault_pc`,
`awaiting_delay_slot`, `prev_pre_pc`, `same_pre_pc_count`, `wp_noprogress_count`,
`prev_mem_size`, `poisoned_targets`, `excursion_is_kernel`, …) steered by
`continue`/`break`. Two phases are already extracted verbatim
(`wp_enter_spec_session` `:115`, `wp_end_spec_session` `:147`,
`wp_append_fragment_insns` `:177`) — the pattern is proven; the decomposition
finishes it.

### 3.1 Shared-state struct + status enum

Fold **all** loop-carried state into one `WpWalkState` struct (extend the
existing `WpAccum` rather than replace it — `acc` stays a member) so helpers take
`WpWalkState&` and mutate in place, exactly as the `auto &bb_pcs = acc.bb_pcs;`
aliasing keeps the body verbatim today (`:382-392`):

```
struct WpWalkState {
    WpAccum acc;
    std::vector<WPBBEntry> chain;
    std::unordered_set<uint64_t> poisoned_targets;
    uint64_t sim_insns, last_fault_pc, prev_pre_pc, prev_mem_size;
    uint32_t same_pre_pc_count, wp_noprogress_count, repeated_fault_pc;
    bool early_exit, fault_stop, awaiting_delay_slot;
    const bool excursion_is_kernel;          // set once at enter
    // + the out-params first_tb_unavail / flush_interrupted
};
```

Each phase becomes a helper returning a status enum the driver `switch`es on;
the enum values are the loop's current `break`/`continue`/fall-through exits made
explicit:

```
enum class WpStep {
    CONTINUE,             // next outer iteration
    RETRY_SESSION,        // flush_interrupted: caller re-runs whole WP
    DOMAIN_CROSS,         // SMEP/PXN terminate (:519-534)
    TRANSLATION_UNAVAIL,  // null tmpl, no flush (:566-616)
    STUCK_BAIL,           // no-forward-progress / nop-slide / wild store
    FAULT_STOP,           // post-completion graceful stop (:1234-1238)
    BUDGET_DONE,          // loop condition exhausted
};
```

### 3.2 Named phases (each a helper, byte-identical body moved verbatim)

| Helper | Source span | Returns |
|---|---|---|
| `wp_enter` (exists) | `:115-139` | void |
| `wp_check_forward_progress` | poison/stuck/nop-slide/rep-overrun guards `:417-534` | `WpStep` (CONTINUE / STUCK_BAIL / DOMAIN_CROSS) |
| `wp_exec_one_tb` | `exec_tb` + null/flush/wild-store handling `:556-631` | `WpStep` (CONTINUE / RETRY_SESSION / TRANSLATION_UNAVAIL / STUCK_BAIL) |
| `wp_walk_fragments` | the inner fragment `for` `:666-1249` | `WpStep` — owns the fragment loop, calling: |
| ↳ `wp_append_fragment_insns` (exists) | `:177-292` | count |
| ↳ `wp_attribute_memops` | `:804-854` | void |
| ↳ `wp_handle_fault_fragment` | `cur_is_fault_fragment` block `:898-1082` | `WpStep` (CONTINUE / FAULT_STOP / STUCK_BAIL) |
| ↳ `wp_commit_bb` | `commit_true_bb_refs` + taken-edge + `make_entry` `:1091-1220` | void |
| `wp_end` (exists) | `:147-166` | void |

The driver `simulate_wrong_path_ext` shrinks to: `wp_enter` -> `while` over
`wp_check_forward_progress` / `wp_exec_one_tb` / `wp_walk_fragments` switching on
`WpStep` -> `wp_end` -> stats. The bodies move **verbatim** (same references,
same order); only the surrounding control flow becomes a named `switch` instead
of `continue`/`break` into a 988-line scope.

### 3.3 Why this is the right shape and how far it goes

The gate is **golden byte-identity** — the decomposition is pure motion, so any
golden diff is a bug in the move, full stop. Decision B (§5) locks the depth:
minimal (extract the three biggest phases, keep the driver loop) vs. full (every
phase a helper, driver is a ~40-line switch). The full form is what `rearch_plan.md`
Phase H's `WpScheduler` needs — a clean `SealedBB -> simulate_wrong_path` seam
with the excursion body already factored — so the recommendation is **full**, but
staged (§4) so each extraction is independently golden-gated.

---

## 4. Phasing

Every stage is a standalone commit series leaving the tree green, gated by the
**standard gate G0**: (1) both golden nets byte-identical — `golden_net.py check`
user-mode 4 ISAs **and** the `--system` CP-user-slice — against *fixed*
pre-captured traces, `setarch -R`; (2) `python -m champsim_tracer_validator all
--isa {x86_64,aarch64,riscv64,mipsel} --run` errors=0; (3) the mutation tier;
(4) run dirs under `/mnt/md0/QEMU/cst_runs`, 16 GiB + timeout caps. Byte-affecting
stages additionally clear the **contention gate G-C** (§6). Stages are ordered by
dependency and by risk (lowest-risk motion first).

### Stage 0 — Baseline lock (no behavior change) — LANDED
Landed the retire-at-return primitive (`faultb_attempt_FINAL.patch`) as the
committed backstop (§1.4), **byte-inert pieces only**: `flush_dropped_prev` +
`flush_frame_unwound` + the `g_last_emit_fault_depth` anchor guard. The
`complete_merge` deeper-frame flush is **DEFERRED to Stage 2/3** (see §1.4;
`TODO(stage2/3)` in `champsim_tracer_path_builder.cc`) because its frame pick is
cross-process-ambiguous until frame identity is `(thread,asid)`-keyed. Both
golden nets stayed **byte-identical** (user 4-ISA + `--system` CP-user-slice),
confirming byte-inertness off the contention path. Captured the **pre**-arc
contention baseline over 50+ varied seeds on a tight 4-core island
(`rearch_s0/drive_baseline.sh`, `check_violations.py`) so the acceptance A/B is
clean — memory rule: intermittent-bug fixes need ~50+ seeds pre **and** post.
The recorded pre-arc JUMP/ANCHOR seed-fail rate and its config are in
`/mnt/md0/QEMU/cst_runs/rearch_s0/BASELINE.txt` (referenced from §6): non-zero
(Stage 0 lands only the backstop, so manifestations 2/3 remain — that is the
residual the suspend-or-seal stages close). **Gate:** G0 met (both goldens
byte-identical, `validator full` green, 4-ISA user battery errors=0, mutation
15/15) + the baseline rate recorded.

### Stage 1 — WP-walker decomposition (byte-identical; independent TU)
§3, staged extraction (each helper its own golden-gated commit): forward-progress
guard -> exec-one-TB -> fault-fragment -> commit-BB -> driver switch. Touches only
`champsim_tracer_wp.cc`, no fault machinery — done first because it is pure motion
and de-risks the largest untested surface before the byte-affecting work, and
because it is the one stage with **zero** dependency on the others. **Byte:**
identical (golden green is the entire gate). **Gate:** G0.

### Stage 2 — Per-`(thread,asid)` frame identity (byte-identical single-process)
§2: thread the seal asid into `frame_idx_for_completion`; demote the byte guard
to a diagnostic. Precedes Stage 3 because suspend/resume matching (§1.3) reuses
the same key — you cannot safely resume-match a suspension without process-
unambiguous identity. **Byte:** identical in user + single-process; changes only
cross-process completion. **Gate:** G0 + a 2-process system A/B (validator
`_multiproc`) showing no cross-process completion regression.

### Stage 3 — Suspend-or-seal, foreign-ASID arrow (byte-AFFECTING system multi-process)
§1.1-1.3 for the foreign-ASID drop (`champsim_tracer_path_builder.cc:897-926`):
add `SuspendedPrev` + `BBChainAssembler::detach_state/attach_state`, the suspend
arrow, the resume arrow, `SUSPENDED_FOREIGN` status + glue. Retire-at-return
(Stage 0) is the displacement/un-resumable backstop. **Byte:** identical user +
single-process (no foreign drops -> no suspension); **byte-affecting** system
multi-process — that IS the fix (the depth-1 level now emits). Every accepted
system diff must be exactly the named improvement (intermediate level emitted /
depth steps by 1); legacy-drop stays behind a flag for A/B parity (Decision D).
**Gate:** G0 + G-C.

### Stage 4 — Suspend-or-seal, abandoned-async arrow
The abandoned-async no-departure-PC drop
(`champsim_tracer_path_builder.cc:837-841`) reuses Stage 3's machinery. Separate
commit because it is a distinct drop site with its own contention signature.
**Byte:** identical user + single-process; byte-affecting system under
async-storm contention. **Gate:** G0 + G-C (incl. an async-heavy long-run).

### Stage 5 — Consolidation: docs + validator semantics
Document suspend-or-seal, `(thread,asid)` frame identity, and the WP-walker phase
map in `docs/architecture.rst` (the CP-flow + WP-flow sections), in the
documentarian voice (describe the model, not the change). Update the
`faultb`-era diag breadcrumbs' documentation. **Gate:** docs build clean;
validator green.

**Dependency graph:** `0 -> {1 ∥ 2} -> 3 -> 4 -> 5`. Stage 1 is fully
independent (different TU) and may run in parallel with Stage 2. Stage 3 requires
0 (backstop) and 2 (identity). Nothing before Stage 3 changes shipped behavior.

---

## 5. Design decisions needing maintainer sign-off

**Decision A — suspended-frame storage, lifetime, and displacement.**
Single `SuspendedPrev susp_` slot (recommended) vs. a small stack of suspensions.
Single-slot means: a **second** foreign/async span opening while a suspension is
held *displaces* it — the older suspension falls back to retire-at-return
(emit its level now via `flush_frame_unwound`, then take the slot for the new
span). A stack preserves both but adds ordering/lifetime surface. Also lock:
a suspension is **orphan-dropped** at `on_segment_open`
(`champsim_tracer_path_builder.cc:143-194`, its `susp_prev` dangles into the
cleared `bb_map_`) — same rule `frames_` already follows — and is
retired-at-return if the stale-frame sweep fires while it is held.
*Recommendation: single slot + retire-at-return on displacement/orphan; the
double-foreign-before-resume case is rare and the backstop already exists.*

**Decision B — WP-walker decomposition depth.** Minimal (three helpers, keep the
driver loop) vs. full (every phase a helper, `WpWalkState` owns all loop-carried
state, driver is a ~40-line switch). *Recommendation: full — it is the seam
`rearch_plan.md` Phase H (`WpScheduler`/#92) requires — but staged per Stage 1 so
each extraction is independently golden-gated.*

**Decision C — frame-identity unification.** Reuse the existing asid machinery
(`pin_effective_asid` + `CtxFrame::asid`, the `46bbff4a2a` keying) as the single
`(thread,asid)` key for resume/block/completion **and** suspend/resume matching,
vs. a parallel completion-only key. *Recommendation: unify — one asid concept
across the whole PathBuilder; the byte guard becomes a pure diagnostic.*

**Decision D — suspend-vs-drop shipped default + A/B flag.** Ship suspend-or-seal
as default with legacy-drop selectable by env (`CST_FOREIGN_DROP`, mirroring
`rearch_plan.md` R2) for byte-parity A/B, vs. remove the drop path outright after
acceptance. *Recommendation: ship suspend default, keep the drop flag through the
next push cycle for A/B, remove it once G-C is 0-fail over two independent
50-seed waves.*

**Decision E — retire-at-return scope under suspend-or-seal.** Keep
retire-at-return as a permanent backstop (un-resumable frames, displacement,
orphan, killed task) vs. re-scope/remove it once suspend proves it covers 2/3.
*Recommendation: keep permanently — it covers cases suspend structurally cannot
(a foreign span that never returns to the pinned context), and its anchor guard
is the safety net that prevents any depth-JUMP -> anchor-violation trade.*

---

## 6. Acceptance gate for the arc

The arc is accepted when **all** hold:

1. **Contention matrix G-C = 0-fail over 50+ varied seeds, pre and post**
   (tight 4-core islands, 3× oversubscription; the Heisenbug-surfacing regime
   that caught 2/3). Post-arc, `check_violations.py` over every kept trace:
   **depth-JUMP = 0 AND anchor-at-unwind = 0**. The pre-arc baseline (Stage 0,
   with `flush_dropped_prev` landed but the suspend arrows not yet) is the A/B
   reference and is recorded in `/mnt/md0/QEMU/cst_runs/rearch_s0/BASELINE.txt`
   (seed-fail rate + depth-JUMP / anchor-at-unwind counts + exact island /
   oversub config); it must show the non-zero fail rate the arc closes, so the
   A/B is real — memory rule: <50 seeds proves nothing; run parallel waves under
   contention.
2. **Both golden nets byte-identical** — user-mode 4 ISAs and the `--system`
   CP-user-slice — at every stage (the WP decomposition and single-process
   fault-identity stages are byte-identical *everywhere*; the suspend stages are
   byte-identical off the contention path).
3. **WP-walker decomposition byte-identity** — Stage 1's every extraction golden-
   green; the decomposed walker produces bit-identical `.cst` to HEAD.
4. `validator full` errors=0 across 4 ISAs including `syscall_fault_nesting`
   (reliable, incl. the `483e93d625` deterministic fault probe), the SMP /
   `_multiproc` system suites, and the mutation tier.
5. Every accepted **system-mode** byte difference is exactly the named
   improvement (an intermediate fault level now emitted; depth steps by 1) —
   nothing else. Legacy drop behind the A/B flag reproduces HEAD byte-for-byte.

This mirrors the multi-ASID arc's bar: an end-to-end trial (there, the mcf
SimPoint system trial) is the ceiling — here, the tight-island contention matrix
**is** that trial, because the bug is a contention Heisenbug, not a steady-state
one.

---

## 7. Reconciliation with `rearch_plan.md`

This arc is a **subset + completion** of `rearch_plan.md`, not a new plan and not
a supersession:

- **Suspend-or-seal was always in the rearch target architecture.**
  `rearch_plan.md` §2 (the target `vcpu_tb_exec` narrative) names it verbatim:
  *"the foreign-ASID drop becomes suspend-or-seal-exactly (legacy drop behind a
  flag for A/B)"*, and R2 in its risk register already scopes the flag. Phase E
  landed the PathBuilder but **deferred** the arrow (the header comment
  `champsim_tracer_path_builder.h:113-119` and the in-code marker
  `champsim_tracer_path_builder.cc:898` are the deferral receipts). **This arc
  executes that deferred arrow** — it is the correctness capstone of Phases E/F,
  not a new phase.
- **Per-`(thread,asid)` frame identity** builds directly on the asid guard the
  keying work (`46bbff4a2a`, itself the multi-ASID arc) added to
  `frame_idx_for_resume`/`frame_idx_for_block`, extending it to completion —
  finishing a keying job the multi-ASID arc started and Phase E left partial.
- **The WP-walker decomposition** is the one genuinely-new piece.
  `rearch_plan.md` §2 explicitly listed *"WP walker internals post-M2"* as
  **untouched**, and Phase H assumed a clean `SealedBB -> simulate_wrong_path`
  seam without scoping the refactor that produces it. This arc inserts that
  refactor as its own byte-identical stage — a **prerequisite for Phase H**, not
  a change to it. Phase H (task #92 `WpScheduler`) remains future work, now
  unblocked.

No `rearch_plan.md` phase is superseded. Phases B (InsnFields diet), G (template
lifetime classes) and H (#92) are untouched and remain open; this arc slots
between the shipped E/F and the future H.

---

## Non-goals

1. **No wire-format change.** `fault_depth`, `fault_anchors`, and per-entry WP
   chains already exist; `CST_MAGIC` frozen. Every stage is in-memory-only.
2. **No new event kind.** Suspend-or-seal consumes the existing FAULT/ASYNC/
   ASID_WRITE events; no ASID/context-switch *event* is added (that non-goal is
   inherited from `rearch_plan.md` §4.3).
3. **No change to the correct pure-async SUSPENDED bail** or the departure-PC
   async reseal — only the two paths that *discard* prev become suspend.
4. **No rewrite of the WP walker's interface** `(branch_pc, correct_target,
   wrong_target) -> chain-by-value` — the decomposition is internal motion only.
5. **No attempt to attribute kernel code per guest thread across vCPU
   migration** — that scope boundary (`validator.py:5089-5111`) stands; the arc
   is the single-address-space, one-core-pinned regime.

---

## Deliverable status

**Implemented.** Stages 0–5 are landed on `champsim-trace` (see the
implementation-status table at the top); the runtime model is documented in
`docs/architecture.rst` (the `.. _suspend-or-seal:` section). The wire format
and `CST_MAGIC` are untouched by every stage. **Not pushed** — the push
acceptance bar (system mode flawless + an end-to-end trial) governs that, per
the maintainer's standing gate.
