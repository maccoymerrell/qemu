# Static templates — fetch/decode coverage of mapped-but-unexecuted code

Consumers that reconstruct a **trace-inferred wrong path** (binary + BTB
replay rather than the plugin's own WP excursions) need instruction coverage
of the *fall-through space*: code that is fetched and decoded on a mispredicted
path but never architecturally executed — predicted-not-taken fall-throughs and
BTB-miss wanders. An executed-only template dictionary cannot resolve those PCs.

The `static_templates` feature closes that gap: at each segment open the plugin
sweeps the guest's mapped executable regions, decodes them through the existing
pipeline, and mints **never-executed STATIC templates** so the dictionary covers
the fall-through / branch-target space. The wire cost is one additive per-insn
flag bit; the runtime cost is one-time per segment and entirely off the
execution hot path.

This document records **P1 as built** (user mode) and the maintainer-corrected
**P2 design** (system mode).

---

## P1 — user-mode prototype (as built)

### Option

`static_templates=1` (default `0`). **User mode only.** In system mode the
option is warned-and-ignored (`g_features.static_templates` is forced off), so a
system trace is byte-identical regardless of the flag — see P2 for the system
enumeration path.

### Enumeration — `qemu_plugin_walk_exec_regions`

A minimal fork plugin API (v13):

```c
typedef int (*qemu_plugin_exec_region_cb)(void *userp,
                                          uint64_t start, uint64_t end);
int qemu_plugin_walk_exec_regions(qemu_plugin_exec_region_cb cb, void *userp);
```

It invokes `cb` once per contiguous **PAGE_EXEC** virtual-address region in
ascending order. The user-mode implementation lives in `accel/tcg/user-exec.c`
(next to `walk_memory_regions` — the linux-user page-flags map *is* the page
table there); `plugins/api-user.c` is compiled target-independently and cannot
reach `target_ulong` / the page-flags header, so the real body could not live
there. `plugins/api-system.c` carries a stub that returns 0 (no regions) — the
P2 page-table walk replaces it.

### Sweep

Armed at every segment open (`start_trace_segment`) and consumed **once**, on
the first in-segment correct-path `vcpu_tb_exec` (a live user-mode vCPU with the
guest's executable regions mapped). The default user-mode window opens at
*install time* with no vCPU and no guest mapped, so the sweep cannot run at
`start_trace_segment` itself — the armed-flag/first-CP-step handshake is what
makes it work for the default window as well as marker/simpoint opens.

`run_static_template_sweep` (holds `data_lock`, matching the dynamic commit
paths):

1. Collect the region bounds via `qemu_plugin_walk_exec_regions` (the walk runs
   under the user-mode `mmap_lock`; only the cheap bounds append happens there —
   the decode/read pass runs after the walk returns).
2. **Linear-decode** each region start-to-end via `qemu_plugin_cap_decode`
   (raw-bytes Capstone detail) → `decode_detail_to_generic` → the
   fragment-splitter's branch-terminator + delay-slot rules
   (`split_tb_into_fragments` logic, replicated for the linear stream). Guest
   bytes are read in ~page chunks through `qemu_plugin_read_memory_vaddr`.
3. Mint each branch-delimited true BB as a STATIC template
   (`commit_static_bb`), and queue each direct branch's decoded target as an
   additional seed — the BTB destination coverage for never-executed
   destinations.
4. **Byte-granular resync.** Fixed-width ISAs decode exactly; on x86 an
   undecodable byte (data in text, mid-instruction desync) advances the scan by
   one byte and continues (fixed-width ISAs step by the 2-byte minimum). Branch
   targets re-seed clean starting points. Never-queried noise templates are
   inert; data-in-text mis-decodes are accepted and documented.

Profile counts stay 0 (never executed). A defensive per-BB length cap
(`CST_STATIC_BB_MAX_INSNS`, 4096) and a per-sweep instruction cap
(`CST_STATIC_SWEEP_INSN_CAP`, 16M) bound the work.

### Late-mapping resweep

The segment-open sweep only sees what is mapped at that instant. Code
mapped afterward — a `dlopen`'d shared library, a JIT code page — needs its
own trigger, not another full segment-open-style walk: `page_set_flags`
(`accel/tcg/user-exec.c`) is the single chokepoint every linux-user mapping
path funnels through (`target_mmap`, `target_mprotect`, `shmat`, the ELF
loader's executable `PT_LOAD` / vsyscall / commpage setup), so it is where
QEMU notifies a registered plugin hook whenever a call grants `PAGE_EXEC`
over a range. This is exposed as a small, dedicated plugin API —
`qemu_plugin_register_exec_region_grew_cb` (`qemu_plugin_exec_region_grew`
is the dispatch entry point, mirroring the single-slot shape of the
ASID-write and devio hooks in `plugins/core.c`) — rather than growing
`qemu_plugin_walk_exec_regions` into something pollable, since the plugin
needs to learn about *new* regions as they appear, not re-enumerate
everything on a schedule.

The hook runs on whatever thread is servicing the guest's mmap/mprotect
syscall, with the linux-user `mmap_lock` held, so the callback
(`static_sweep_region_grew_cb`) only pushes the range onto a queue —
`g_pending_sweep_regions`, guarded by a dedicated leaf lock never held
across a guest-memory read or `exec_lock`/`data_lock` acquisition. The
queue drains on the owning vCPU's next correct-path TB exec
(`events_path_step`), where `exec_lock` is already held: a cheap
atomic-flag check costs nothing on the hot path when nothing is pending,
and `run_static_template_resweep` reuses the segment-open sweep's decode
core (factored out as `sweep_regions`) scoped to just the queued ranges,
sharing its caps, its `commit_static_bb` dedup, and its stats. Duplicate
`(start, end)` pairs queued between two drains collapse to one sweep; a
region swept in an earlier drain is not otherwise excluded from a later
one, since a re-mprotect'd JIT page may legitimately carry new code, and
resweeping unchanged content is a cheap no-op via `commit_static_bb`'s own
key dedup rather than a correctness hazard. A region unmapped again before
its queued drain runs — the one race a purely synchronous, walk-then-sweep
design cannot hit — is bounded by `CST_STATIC_STALE_DESYNC_LIMIT`
consecutive zero-progress desyncs, so an abandoned resweep costs a small
constant rather than a byte-by-byte walk to the (now stale) region end.

User mode only, by construction: the dispatch call site lives in
`accel/tcg/user-exec.c`, which system builds do not compile (they build
`user-exec-stub.c` instead), so registering the hook under system
emulation is a harmless no-op with no call site to fire it — exactly
mirroring `qemu_plugin_walk_exec_regions`'s empty system-mode report.

### Template lifetime & dedup by construction

A third `TmplLife` class, **STATIC**, sits alongside CODE/SPEC. STATIC templates
live in a segment-scoped `static_map_` — a **sibling of `bb_map_`**, keyed by
the same `(asid_root, start_pc)` (asid_root is 0 in user mode) — dropped
wholesale at `clear_bb_map`.

The executed dictionary (`bb_map_`) is never touched by the sweep. Dedup is by
construction, at serialization:

- `commit_static_bb` dedups within `static_map_` (a re-sweep of the same block
  is idempotent).
- The writer serialises only static templates whose key is **not shadowed by an
  executed `bb_map_` entry** (`for_each_static` skips shadowed keys; dynamic
  wins). A block that is both swept and later executed is therefore carried by
  its executed CODE template with no STATIC bit — the flag *clears on
  execution*, realised by the executed twin shadowing the static one.

STATIC templates are **not** assigned an id from the executed template-id
counter. `for_each_static` assigns each a fresh section-local id at
serialization, above every executed id in that segment's templates section
(referenced by nothing, collision-free). This is what keeps executed blocks
numbered exactly as they would be with the sweep off — the trace **body stays
byte-identical**.

### Wire — one additive flag bit

`CST_INSN_FLAG_STATIC` (per-insn flags byte bit 3, previously reserved). Stamped
on every instruction of a STATIC template, uniform across the block (a whole
block is static or it is not), exactly as `CST_INSN_FLAG_SYSTEM` rides the
privilege stamp. It is advertised through the header's open `insn_flag` name map
**only when the sweep is active** — the trailing map entry is trimmed off when
`static_templates` is off (the physaddr / devio pattern), so a trace without the
sweep keeps the historical 7-entry vocabulary and is byte-identical.

STATIC templates ride the normal templates section as unreferenced dictionary
entries — legal (the dangling lint is body→template only); `cst_audit` rolls up
to 100% with them accounted.

### Caps & stats

Reported at plugin exit (`Static-template sweep: ...`): sweeps, regions,
region_bytes, insns, static_bbs, desync_reseeds, targets_seeded, cap_hits, wall
time and MB/s over the swept footprint.

### Measured (per-ISA, seed-driven diamond)

| ISA | region | insns | static BBs | desync-reseeds | time |
| --- | ------ | ----- | ---------- | -------------- | ---- |
| x86_64  | 12 KiB | 3.5K | 340 | 4163 | 0.03 s |
| aarch64 | 8 KiB  | 1.9K | 258 | 294  | 0.02 s |
| riscv64 | 12 KiB | 5.0K | 387 | 319  | 0.02 s |
| mipsel  | 8 MiB (static bin) | 2.1M | 1155 | 985 | 3.4 s |

x86 carries the highest desync-reseed rate (variable width + data in text); the
fixed-width ISAs desync only on true data-in-text. Cost is dominated by the
per-insn decode + classify + commit (the same per-insn work the dynamic path
does), so throughput tracks the executable footprint, not execution length.

### Gates met

- **Flag OFF byte-identical:** user golden net GREEN (25 cells + SVG goldens
  byte-identical, validator errors=0); the shared Capstone handle-cache change
  in `disas/capstone.c` produces identical decodes on the normal path.
- **Flag ON decode-diff (diamond, `wp=0`):** the executed templates and the
  whole **body** are byte-identical to the flag-off trace; the only delta is the
  appended STATIC templates plus the header advertising the new flag name.
- **`cst_audit` 100% / `cst_decode --strict` rc=0** with static templates
  accounted.
- **Coverage oracle** (`features.wrong_path_coverage`, 4 ISAs): with
  `static_templates=1`, every executed conditional-branch fall-through resolves
  to a template start_pc, never-executed conditional-branch fall-throughs are
  covered, and never-executed direct-branch targets resolve (BTB). The
  disabled-sweep run loses the never-executed coverage entirely, proving the
  oracle has teeth.

### Known P1 limitations

- **x86 alignment.** Functions reached only through indirect transfers (never a
  direct-branch seed) are covered by the linear scan, which may enter them at a
  byte offset that disagrees with real execution; such mis-aligned blocks are
  inert noise at never-queried PCs.

Late mappings (a dynamically-loaded library, a JIT page mapped after the
segment-open sweep already ran) were an earlier P1 gap — the sweep only saw
what was mapped at open, so a window opening at the loader's first
instruction (`icount:start=0`) never covered shared libraries mapped
afterward. See **Late-mapping resweep** above: `qemu_plugin_exec_region_grew`
closes it by resweeping newly-exec-permitted regions as they appear, for any
window shape.

---

## P2 — system mode (maintainer-corrected design; not yet built)

System mode has no user-mode page-flags map; the executable footprint is a
guest-owned page table. **Enumerate by walking the page tables of the owned
roots** — a `monitor info mem`-style walk of each owned address space's paging
structures.

Load-bearing corrections:

- **PTE validity is the truth; TLB residency is NOT a criterion.** Walk the
  page tables and admit every valid, executable-permission PTE, whether or not
  its translation is currently TLB-resident. Read the guest bytes with a
  probing read (`probe = true`) so enumeration never demand-pages the guest or
  perturbs its state.
- **TLB-fill events are change-notifications only.** A code-page TLB fill is a
  hint that a mapping may have changed/appeared; it triggers a **re-consult of
  the page tables** for late mappings, rather than being itself the criterion
  for coverage (residency ≠ coverage).
- **Re-walk cadence.** Periodic re-walk, or a re-walk on schedule-in of an owned
  root, is the alternative to event-driven re-consultation for picking up late
  mappings across a long system trace.

Keying and the wire bit carry over unchanged from P1: kernel-VA blocks key to
the shared kernel sentinel bucket (KPTI-off canonical model), user-VA blocks to
the owning process root; STATIC rides the same `CST_INSN_FLAG_STATIC`.

`qemu_plugin_walk_exec_regions`'s system stub (returns 0 today) is where the
page-table walk lands, or a distinct system-mode enumeration entry point is
added — to be decided when P2 is built.

---

## Opportunistic alternate minting

The system-mode coverage P2 chases — never-executed fall-through and
branch-target templates without a user-mode page-flags map — is delivered by a
different mechanism that supersedes the P2 page-table walk: **opportunistic
branch-alternate minting**.  It is mode-independent (it needs no region
enumeration at all) and rides the same `static_templates=1` option, so
`static_templates=1` now means *sweep (user) + alternate minting (both
modes)*.  The P1 sweep is retained as-is.

### The idea

The never-executed space a trace-inferred wrong path fetches is, block by
block, the **untaken side of a branch**.  Rather than enumerate the whole
executable footprint up front, the plugin mints that side exactly when a
branch is evaluated: at every branch the correct path or a wrong-path
excursion resolves, it checks whether the side NOT followed already has a
template; on a miss it decodes that one true BB — through the same
`qemu_plugin_cap_decode` → `decode_detail_to_generic` → fragment-splitter
machinery the dynamic path uses — and mints it as an ordinary never-executed
template.  The alternate is never traced as a wrong-path block: no `WPBBEntry`,
no dynamic state, no body record — only a dictionary entry.

Coverage is therefore **convergent, not eager**: the dictionary fills in as
branches are seen over the run, not all at once at segment open.  A branch
never evaluated in the window contributes no alternate (correctly — a
consumer never fetches its untaken side either); a rarely-taken branch's
alternate appears the first time the branch is evaluated.  This is a weaker
guarantee than the sweep's "every mapped byte decoded", and an honest one: it
matches exactly the fetch space a mispredict-driven consumer reaches from the
branches the workload actually executed, which is the space that matters.

### Two hook sites

Complementary, covering the two gaps a wrong path alone leaves:

1. **Wrong-path walk** (`wp_commit_bb`, the decomposed `WpStep` pipeline).  A
   branch *inside* a wrong-path block resolves one direction (the excursion
   follows its computed successor); its untaken side is never walked, so an
   executed + wrong-path dictionary misses it.  The hook mints that side —
   the statically-known alternate of a conditional-direct terminator (taken
   target = the decoded immediate, not-taken edge = the fall-through) — after
   the block is committed.  This fills the *deep* gap.

2. **Correct-path seal** (`collect_finalized_bbs`, the PathBuilder seal walk).
   When a branch's wrong-path fork will NOT launch — `wpprune` pruned it,
   wrong-path is disabled (`wp=0`), or paging is off — nothing decodes its
   untaken side, so the seal queues that side (`resolve_wrong_target`'s output,
   the not-taken block) for minting once `data_lock` is released.  When the
   fork DOES launch, the wrong path itself covers the untaken block (and its
   inner branches feed hook 1), so the seal leaves it.  The
   translation-unavail tail — a fork that launched but could not fetch its
   first target — is caught in `emit_finalized_bb` after the walk.

### Keying, lifetime, and the byte-identity discipline

Alternates live in a segment-scoped `alt_map_`, a sibling of `bb_map_` and the
sweep's `static_map_`, keyed by the same `(asid_root, start_pc)` — kernel VAs to
the shared kernel sentinel bucket, user VAs to the owning process root, via the
established VA-domain classification.  Dedup is by construction: a mint whose
key is already in `bb_map_` (executed) or `alt_map_` (minted) is skipped
(`alt_or_bb_covered`; existing wins, `find_existing_true_bb` semantics).

The **body stays byte-identical** to a run with the option off, by the same
shadowing / id-ordering discipline P1 uses.  An alternate takes a placeholder
id at commit and is assigned its real, section-local wire id lazily by
`for_each_alt` at serialization — strictly above every executed *and* static
id — so it never consumes an id an executed block would otherwise take; the
executed dictionary numbers exactly as it would with the option off.  At
serialization an alternate whose key is shadowed by an executed (`bb_map_`) or
swept (`static_map_`) entry is dropped: the executed template wins (real id,
real profile), the swept one wins (with its `CST_INSN_FLAG_STATIC`), and the
flag-less alternate covers only what neither reached.

Unlike a STATIC template, an alternate carries **no wire flag** (life `CODE`,
so `write_insn_descriptors` stamps no `CST_INSN_FLAG_STATIC`): it is an
ordinary never-executed dictionary entry, indistinguishable on the wire from
any block that happened not to execute — because that is exactly what it is.

### Guest-read policy, bound, and stats

Guest bytes at the alternate's PC are read with the probing
`qemu_plugin_read_memory_vaddr` (mapped page → decode; unmapped → skipped and
counted), so enumeration never demand-pages or perturbs the guest — the same
valid-mapping policy the wrong path obeys, and the reason a genuinely-unmapped
fall-through is left uncovered (a consumer would fault there too).  A
per-segment mint budget (`CST_ALT_MINT_BUDGET`) caps the decode+mint work; the
presence test (one hash lookup per evaluated branch) is always allowed, and
the decode fires only on a miss, so after warmup — every reachable alternate
already minted — the steady-state cost is one lookup per branch.  Reported at
exit (`Branch-alternate minting: ...`): `checks`, `mints`, `skips_unmapped`,
`budget_hits`.

### Measured

* **Flag OFF** — user golden net GREEN (25 cells byte-identical, validator
  errors=0); the feature paths are inert when `static_templates=0`.
* **Flag ON, body byte-identical** — a deterministic freestanding diamond
  (all four ISAs), traced with `wp` on and under `wpprune`, has a **body**
  byte-identical to the flag-off trace; the delta is templates-section-only.
  A system trace's canonical user-code slice is likewise identical off vs on.
* **Coverage (system mode, alternate minting alone — the sweep is off there)**
  — on a `qemu-system-x86_64` virtio-blk marker-window trace, executed
  conditional-branch fall-through resolution rises from ~84 % to **99.1 %**
  (unresolved ~665 → 35); the residual is genuinely-unmapped kernel
  fall-throughs the probing read cannot (and should not) cover.  In user mode
  the sweep already drives this to 0; minting adds the branches the sweep's
  linear scan reaches only indirectly.  The mint here is ~1 200 alternates.
* **Footprint & cost (user mode, mcf 100 M window, sweep + minting)** — the
  minting side mints **2 590** alternates on top of the sweep's 129 504 static
  BBs: the template-section growth is proportional to the distinct
  *evaluated-branch* alternates, far leaner than an eager whole-footprint
  walk (which for mcf would decode millions of blocks).  Runtime cost is
  dominated by the *check latch*: the per-`bb_tmpl` `alt_checked_{cp,wp}` flags
  cut the presence check from **222 million** (once per WP-block commit) to
  **3 759** (once per distinct block), so minting's own hot-path cost is a
  handful of hash lookups over the whole run — unmeasurable.  The residual
  wall-time delta with `static_templates=1` (~2 % on mcf) is the P1 sweep's
  one-time decode + serialisation of its 129 K static templates, not the
  minting; in system mode, where the sweep is off, only the minting cost
  remains.
