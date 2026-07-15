# Whole-System Multi-ASID Tracing — Design Plan

Follow-on arc to the single-address-space tracer. Goal: carry the **address
space (ASID)** alongside the thread in the body stream so memory is keyed by
`(asid, vaddr)` across multiple processes, making whole-system capture coherent.
This is the work anticipated by the single-address-space scope boundary.

Status: **DESIGN LOCKED** (all four open questions resolved by the maintainer,
below). Phases 1/2/3A/B1 + kernel-context fold implemented; internal-cache
asid keying in progress.

---

## 0. REQUIRED GUEST CONFIGURATION: run system mode with KPTI DISABLED

**This is the canonical way to run system-mode tracing** (kernel boot arg
`pti=off` / `nopti`, and analogous page-table-isolation features off on other
ISAs): the kernel then lives in each process's page tables under the process's
own root, so **the kernel shares the process's ASID** — one address space per
process, kernel included, exactly the model the wire's `(asid, vaddr)` key
assumes.

KPTI and other OS side-channel isolation features are **modeled externally by
the consumer**, not captured in the trace. This is fully reconstructible
because:
- every block carries the per-insn **system bit** (`CST_INSN_FLAG_SYSTEM`), so
  kernel vs user execution is exact; and
- **kernel data pages and user pages are never shared** (disjoint VA ranges),
  so a consumer can re-impose KPTI-style separation (or any isolation policy)
  on the address stream without ambiguity.

Running with KPTI **enabled** still works (the kernel's isolated root gets its
own asid index; the kernel-context fold keeps thread/regfile keying on the
process), but it splits kernel memory references onto a separate asid and is
NOT the supported baseline — the trace then reflects one specific mitigation
configuration instead of letting the consumer model it.

---

## 1. Context model

The context of a body record becomes the pair **`(thread_id, asid)`** instead of
just `thread_id`.

- **Mandatory initial declaration.** Every trace/segment opens with an initial
  `BODY_TAG_THREAD_SWITCH` **and** `BODY_TAG_ASID_SWITCH` before the first
  entry, declaring the context the trace starts in. The stream is
  self-describing from entry zero, in **all** modes.
- **Independent switches.** Emit a switch record when *either* dimension
  changes: thread-only (intra-process thread switch), both (process switch), or
  asid-only (a kthread borrowing a user mm, `kthread_use_mm`).
- **Consumer contract:** memory is keyed `(asid, vaddr)`; a switch record
  rebases that dimension of the current context. Identical VAs under different
  asids are different physical memory.

Single-process and user-mode traces emit the initial pair and then no further
asid switches — the asid dimension only "activates" with more than one address
space.

---

## 2. ASID identity — the stable key (not the raw field)

The wire carries a **compact monotonic asid index**, assigned **on first
sighting** (exactly like the guest-thread `tid` and the register-file snapshot).

Each index maps to an identity = the **page-table root physical address** (pgd):

| ISA | Root register | Notes |
|-----|---------------|-------|
| x86_64 | `CR3` | mask PCID + NOFLUSH bit 63 (already done, `6db5eeaa47`) |
| aarch64 | `TTBR0/1_EL1` base | strip the ASID field; keep the base phys |
| riscv | `SATP` PPN | |
| mips | **marker code-page physical address** | see the MIPS deviation below |

**Why root-phys, not the architectural ASID field:** MIPS EntryHi ASID is 8-bit
and aarch64 TTBR ASID is 8/16-bit — they roll over and get reused over a long
trace (the reuse hazard the pinned-process work already solved). The pgd
root-phys is uniform across ISAs and stable.

**MIPS anchor deviation (Stage B3):** MIPS exposes no readable pgd root — the
CP0 audit in `mips_get_plugin_state` found `Context.PTEBase` is a per-CPU
constant on 24K/34K-class guests (the kernel keeps the pgd in the in-RAM
`pgd_current[]` array), and `qemu_plugin_get_addr_space_id()` therefore returns
the bare 8-bit `EntryHi.ASID`, which cannot be the stable wire root. Stage B3
uses the **physical page address of the process's marker code page** as
`root_phys` (a real, stable physical anchor that virtual aliasing cannot forge
and an ASID rollover cannot move; `marker_anchor()`), with the FNV of that page
as `sig`. Each owned process (`OwnedProc`) carries its own `(root_phys, sig)`,
mapped through `asid_root_to_index` to a compact index that survives an
`EntryHi.ASID` rollover — the raw value is never the wire key. User mode
(asid 0, one address space) keeps `(0, 0)` so those traces stay byte-identical.
Two concurrently-owned processes always hold **distinct** `EntryHi.ASID` values
(recycling only follows death), so the internal template store keyed by the live
value still separates them; only the wire index needed the owner-derived anchor.

**pgd reuse after process death** (a freed pgd page reallocated — rare):
disambiguate with a content **signature** (FNV of the pgd / first code page),
reusing the `vpage → {ppage, sig}` machinery. A reused root-phys with a new
signature is a **new** asid index.

**Machinery already present:** `asid_match` (uint64) + `asid_write_track_cb`
track the ASID root today (pinned fast-forward); `qemu_plugin_vaddr_to_paddr`
(API v10) resolves phys.

---

## 3. Detection (mostly already built)

- **ASID switch:** the synchronous ASID-write hook
  `qemu_plugin_register_asid_write_cb` (API v9, `27cce05072`) fires on writes to
  the page-table root. On fire: resolve root-phys → asid index; if it differs
  from the current, arm a pending asid-switch.
- **Thread switch:** guest-thread identity via the thread-pointer registers —
  arm a pending thread-switch on change.
- **Flush before the next entry** so the switch record precedes the entries it
  scopes.

Whole-system is therefore largely a **wire-format + emit + gating** change that
*reuses the existing hook*, not new MMU plumbing.

---

## 4. Wire format — first-sighting inline (DECISION 2)

- **`BODY_TAG_ASID_SWITCH` (new, tag 5)** — sibling to `BODY_TAG_THREAD_SWITCH`
  (tag 2). Payload: `asid_index` (ULEB). The **first** appearance of an index
  additionally carries its identity (`root_phys` + `sig`) **inline**, mirroring
  how the register file is emitted on a thread's first sighting.
- **No header asid table.** ASID switching is inherently an in-body event (like
  thread switching), so a header table would not cleanly separate asid out of
  the body anyway; and the asid count is not guaranteed small/bounded over a
  long whole-system trace. First-sighting inline keeps the format uniform with
  the existing regfile/tid pattern and stays streaming-friendly.
- `BODY_TAG_THREAD_SWITCH` unchanged in shape; now emitted initially too.
- **Regfile keying:** the register file is thread state, not asid state, so
  `BODY_TAG_REGFILE` (tag 4) stays per-thread — but keyed on the **`(asid,
  thread)`** pair (a thread-pointer value can collide across processes).

**Format epoch / `CST_MAGIC` (DECISION 1):** the format is not public yet, so
the magic is a **non-issue** — the wire changes freely and no back-compat with
existing traces is owed. No bump is required (and per CLAUDE.md we do not bump
it now); it can be revisited at a formal release.

---

## 5. Gating — marker-driven, two selectable modes (DECISION 3)

The whole point of whole-system is user choice over *what* gets traced, keyed on
the trace **marker** ("the magic") a process emits:

- **Latch mode:** latch onto **each process that emits the marker** and trace
  only those tagged asids (multiple processes independently opt in).
- **Trace-all mode:** the **first** marker emission begins tracing **everything**
  (all contexts), and tracing **ends when the marker ends**.

So the pin/scoreboard generalizes from a single-pin gate into a marker-driven
context filter with these two policies (a plugin option). Detection and tagging
are identical; only the "is this context in-scope" predicate differs.

---

## 6. Windows, segments, icount (DECISION 4)

- **The icount clock stays the tagged program's user-space instructions**, as
  today. Segment and icount positions remain relative to the marker-invoking
  program's user-space instructions.
- **Multiple marker-invoking programs:** the segment / icount / window machinery
  is **kept in place and still works**, but the totals become **cumulative
  across all tagged processes' user-space instructions** (a single summed
  clock). Kernel instructions and non-tagged contexts do not advance it.
- **SimPoints are single-program-only.** A SimPoint is a phase of *one*
  program's execution, so with multiple marker-invoking programs simpoints are
  **invalid** — the simpoint window-selection is disabled/meaningless there,
  while the underlying segment/icount/totals machinery is preserved.

---

## 7. Kernel attribution (under the §0 KPTI-off baseline)

- The kernel is **one physical instance** mapped into every asid (§0: KPTI
  off), and **kernel data pages and user pages are never shared** (disjoint VA
  ranges) → a kernel VA is unambiguous regardless of asid tag.
- **Kernel BB asid tag = the owning PROCESS asid** (the kernel-context fold's
  `ctx_asid_index`): the kernel shares the process's address space, so its
  blocks carry the process's asid, distinguished by the per-insn **system
  bit**. This makes the trace **KPTI-invariant**: even if the guest runs KPTI
  (unsupported baseline), the isolated kernel root never appears as a wire
  asid — kernel work still folds to the process, and the consumer models
  isolation externally (§0).
- **Template-cache identity for kernel code is shared** (one kernel): a kernel
  true-BB keys its **serialised template** (`bb_map_`) into one shared kernel
  bucket (sentinel asid), not the per-process root — the same kernel code at
  the same VA is one serialised template, never duplicated per process.
  - *Safety refinement (implementation):* the sentinel bucket's collision-
    safety rests on kernel/user VA disjointness, so it must admit **only**
    genuine kernel VAs. A wrong-path walk can speculatively *translate* a user
    VA while at kernel privilege and mis-stamp it `is_system` — so only a
    **CP-confirmed** kernel block (correct-path privilege, `is_system &&
    is_system_cp_confirmed`) enters the shared bucket; wrong-path commits key
    by their live process root, never the sentinel. Otherwise two processes'
    user code at one VA would conflate in the shared bucket. The *internal*
    fragment-chain dedup index (`tb_chain_dedup_`/`spec_chain_index_`) likewise
    stays per-process (live root), so a wrong-path mis-stamp there is at worst
    a per-process duplicate, never a cross-process reuse — the shared identity
    is only the wire-visible template.
- **Kernel-thread attribution is the ceiling** (unchanged): no kernel-privilege
  thread register exists, so *which process's* kernel work a kernel BB belongs
  to is best-effort via the entering context and degrades under cross-vCPU
  migration. Documented limitation, not a regression.

---

## 8. Validator coverage

New multi-ASID suite over a 2+-process workload (two marker-emitting programs, or
a fork/exec), asserting:

- initial `(thread, asid)` record present;
- asid-switch records at process switches; **`(asid, vaddr)` disambiguation**
  (same VA in two processes → different memory);
- kernel shared-memory consistency across asids;
- compact-index stability (no spurious new indices from raw-ASID rollover — the
  reuse-signature path);
- both gating modes (latch vs trace-all) select the right context set;
- cumulative-icount correctness across tagged processes; simpoints refused with
  >1 marker program while segments still emit.

Acceptance gate: a **whole-system multi-process trial**, analog to the mcf
SimPoint trial that gated the single-address-space push.

---

## 9. Docs

`champsim_tracer_format.md` + the Sphinx tree: the `(thread, asid)` context
model, the `(asid, vaddr)` memory key, first-sighting asid identity, the
mandatory-initial record, the two gating modes, cumulative-icount /
simpoint-single-program semantics, and the kernel-thread ceiling.

---

## Phasing

1. **Wire** — `BODY_TAG_ASID_SWITCH` (first-sighting inline identity) + mandatory
   initial `(thread, asid)` pair + `(asid, thread)`-keyed regfile/tid tables.
   Single-asid traces: initial record, no further switches.
2. **ASID identity** — hook → root-phys → compact first-sighting index +
   reuse-signature disambiguation.
3. **Gating** — marker-driven filter with the two modes (latch / trace-all).
4. **Windows** — cumulative-icount across tagged processes; disable simpoint
   selection under >1 marker program while preserving segment/total machinery.
5. **Kernel attribution** — current-root tag + document the thread ceiling.
6. **Validator** — multi-ASID suite + multi-process acceptance trial.

## Resolved decisions

1. **Magic:** non-issue (format not public) — change freely, no bump.
2. **ASID identity:** first-sighting **inline** (mirrors regfile); no header
   table.
3. **Gating:** user selects **latch-per-marker-process** or
   **trace-all-in-marker-window**.
4. **Windows:** icount = tagged programs' user-space instructions, **cumulative**
   across multiple; **simpoints single-program-only** (machinery preserved,
   selection invalid with >1 marker program).
