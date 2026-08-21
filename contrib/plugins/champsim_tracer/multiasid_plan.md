<!-- HISTORICAL DESIGN PLAN — SUPERSEDED.

     The owned-ASID-set / root-identity design this plan locked was
     superseded twice over by the latched-vaddr CONTENT GATE (REDUCTION
     v3/v4, 2026-08-21): whether a context is traced is decided by
     reading the marker sequence's bytes at each latched window vaddr
     through the live context at every committed address-space change.
     No root, ASID or process id is stored or compared as an identity;
     recycling, migration and narrow-ASID identity are non-concepts;
     the wire's asid dimension carries LABELS (live values, compact
     first-sighting indices; the sig word is permanently 0).  The
     surviving truths of this plan — KPTI-off as the canonical
     configuration and the (thread_id, asid) context model with
     independent switch records — are carried by concepts.rst and
     format.rst §4.1a/§4.2a, which are authoritative.  The text below
     is retained for the record only.  -->

# Whole-System Multi-ASID Tracing — Design Plan

Follow-on arc to the single-address-space tracer. Goal: carry the **address
space (ASID)** alongside the thread in the body stream so memory is keyed by
`(asid, vaddr)` across multiple processes, making whole-system capture coherent.
This is the work anticipated by the single-address-space scope boundary.

Status: **DESIGN LOCKED** (all four open questions resolved by the maintainer,
below) and **IMPLEMENTED**. Phases 1/2/3A and Stage B1/B2/B3 are landed, along
with the kernel-context fold, internal-cache asid keying, the KPTI-off canonical
model, per-entry compact asid indices, and the `latch` / `trace-all` marker
policies with the `latch_timeout` dead-latch backstop. The `(asid, thread)`
context and `BODY_TAG_ASID_SWITCH` are on the wire (see
`champsim_tracer_format.md` §4.1a).

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
