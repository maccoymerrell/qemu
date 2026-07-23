# Self-Modifying Code Support — Design Plan

**Prepared for:** Maccoy Merrell (sole maintainer), for sign-off before any code
is written. **Status: DECISIONS LOCKED 2026-07-23 — ready for implementation.** Branch
`champsim-trace`. The wire format gains **no new records**; `CST_MAGIC` is
untouched.

## 0. Problem

The tracer has no mechanism to introduce *updated* template blocks: templates
are immutable dictionary entries and the internal cache holds one entry per
`(asid_root, start_pc)`. Today a detected code mutation is refused (the
translation-time SMC detector's drop path). Supporting SMC must avoid state
explosion from (1) non-executed intermediate mutations (JIT regions written
many times before entry; text writes during loading) and (2) the hard stopper:
real but excessively numerous minor executed modifications (inline-cache and
call-target patching).

## 1. Design: versioned keys, lazy mint-on-execution (maintainer option A)

Two standing facts make option A near-free:

- **Body entries reference `template_id`, never PC.** The PC key is only the
  internal cache key. Multiple templates at one `(asid, pc)` are already
  representable on the wire; the body's references carry the version timeline
  implicitly (each entry names the id that was live when it executed).
- **The dictionary serializes once, at segment finish.** Retired revisions
  simply serialize alongside their successors.

Mechanism:

1. **Detection = the existing SMC detector's seam.** On a CP retranslation
   whose cached template holds different bytes, the response changes from
   refuse/drop to **mint a revision**: new template (new id), generation-bump
   the `(asid_root, start_pc)` cache slot. The old template is retained (body
   entries reference it) and serializes normally. Explicit alternative B (a
   body record announcing updates) is **rejected**: for executed code it adds
   nothing the next body reference doesn't imply, and for non-executed code it
   is exactly the eager announcement constraint (1) forbids.
2. **Laziness kills constraint (1) by construction.** A revision mints only
   when a mutated block *re-executes*. Writes to never-translated code never
   surface at all (no TB, no invalidation event). A region written N times
   and entered once mints one revision — the state at execution.
3. **Constraint (2) — two defenses:**
   - **Content-signature reuse.** Retired revisions are remembered by
     `(pc, content_sig)` (FNV, existing machinery). A mutation returning to a
     previously-seen state **reuses that template id** — A/B/A/B patching
     resolves to the distinct-state count, not the transition count.
   - **Per-PC revision cap** (`smc_revisions=N`, §5-A). Beyond N distinct
     states, stop minting: keep referencing the last revision and set a
     `mutation_overflow` marker (stat + flag per §5-B) — the consumer is told
     bytes at this pc are approximate from that point. The cap is the
     backstop regardless of dedup quality (heap-runaway precedent).
4. **Speculation guard.** Revisions mint **only from CP-confirmed
   translations**. A wrong-path spec-translation observing mid-write bytes
   must never version a template (the established mis-stamp class). Alternate
   minting follows revisions for free: a new template id carries fresh
   `alt_checked` latches.
5. **Consumer contract.** The pc-indexed table becomes "templates per pc, in
   body-reference order"; the live version at any stream position is the one
   the entries reference. Streaming consumers already maintain exactly this
   map. Decoder: expose the per-pc version list; audit: count revisions +
   overflow events.

## 2. Interactions audited before implementation

- The poison/false-drop fixes (merge content guard) assumed refusal semantics —
  the revision path must preserve the same-VA cross-process byte-guard logic.
- WP fault-frame `frame_idx_for_completion` byte-content diagnostics: a
  revision changes bytes at a pc; frame matching is (thread,asid)-scoped so
  correctness holds, but the byte diagnostic may report drift (expected —
  diagnostic only).
- tb_flush / template lifetime: retired revisions are CODE-lifetime (body
  references pin them); the SPEC reclaim path is unaffected.

## 3. Verification plan

- A dedicated SMC workload family in the validator generator: (a) patch-once
  (rewrite a block, re-execute — two revisions, both referenced correctly);
  (b) flip-flop (A/B/A/B — exactly two revisions minted, ids alternate);
  (c) write-without-execute storms (zero revisions); (d) cap overflow
  (N+1 distinct states — overflow marker set, trace decodes clean).
- Oracles: body references resolve to the byte-correct revision at every
  position (extend the template_raw_bytes check to be version-aware); audit
  buckets for revisions/overflow; mutation-tier case (corrupt a revision's
  bytes → caught).
- Gates: flag-off (or SMC-inactive workloads) byte-identical on both golden
  nets; 4-ISA battery; features tier; user + system SMC workloads (system:
  a kernel-module-free patching guest program under the marker window).

## 4. Phasing

1. Revision mint at the detector seam + content-sig reuse + cap (user mode
   first; the seam is mode-independent but validation starts user).
2. Decoder/audit version awareness + oracles + SMC workload family.
3. System-mode validation (same code path; adds the (asid, pc) keying案 —
   already correct by construction since the cache key carries asid_root).

## 5. DECISIONS LOCKED (2026-07-23)

- **A — cap `smc_revisions=1024`**: the cap is a BUG DETECTOR, not a fidelity
  budget (maintainer). No real SMC pattern approaches it; reaching it means a
  tracer defect (false-mutation loop) or a pathological runaway. Sized far
  above legitimate use.
- **B — overflow emits a LOUD WARNING** (stderr, per-segment, like the
  established warning class) + stats; the degrade (keep referencing the last
  revision) remains the safe behavior, but the event is an anomaly signal,
  not an expected mode. No wire bit.
- **C — always-on**: SMC handled transparently; the refusal path retires.
- **D — no provenance bit**: duplicate (asid,pc) is self-evident.

### (original decision text, for the record)

- **A — cap default `smc_revisions=N`**: proposed 8 distinct states per pc
  (beyond that, overflow degrade). Higher = more fidelity for pathological
  JITs at template-heap cost.
- **B — overflow marking**: template flag bit (visible per-template on the
  wire) vs stats-only. Proposed: one template bit (`mutation_overflow`) — a
  consumer modeling code caches deserves the honesty signal in-band.
- **C — gating**: always-on (SMC handled transparently; refusal path retired)
  vs `smc=0/1` option (default off, refusal preserved). Proposed: always-on —
  the lazy design costs nothing when no code mutates, and two behavior modes
  are a validation burden.
- **D — revision provenance bit**: mark revision templates with a wire bit vs
  rely on the self-evident duplicate-(asid,pc) property. Proposed: no bit
  (self-evident; keeps the flag space clean).
