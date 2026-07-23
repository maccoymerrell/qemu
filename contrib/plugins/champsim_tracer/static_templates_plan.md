# Static templates — fetch/decode coverage of never-executed code

Consumers that reconstruct a **trace-inferred wrong path** (binary + BTB
replay rather than the plugin's own WP excursions) need instruction coverage
of the *fall-through space*: code that is fetched and decoded on a mispredicted
path but never architecturally executed — predicted-not-taken fall-throughs and
BTB-miss wanders. An executed-only template dictionary cannot resolve those PCs.

The `static_templates` feature closes that gap. This document records the arc:
an eager executable-region **sweep** was built first (P1, user mode) with a
system-mode page-table-walk successor sketched (P2); both were **superseded**
by **opportunistic branch-alternate minting**, which is what the feature is
today. The sweep and the P2 walker have been retired from the tree.

---

## What the feature is now — opportunistic branch-alternate minting

The never-executed space a trace-inferred wrong path fetches is, block by
block, the **untaken side of a branch**. Rather than enumerate the whole
executable footprint up front, the plugin mints that side exactly when a branch
is evaluated: at every branch the correct path or a wrong-path excursion
resolves, it checks whether the side NOT followed already has a template; on a
miss it decodes that one true BB — through the same `qemu_plugin_cap_decode` →
`decode_detail_to_generic` → fragment-splitter machinery the dynamic path uses
— and mints it as an ordinary never-executed template. The alternate is never
traced as a wrong-path block: no `WPBBEntry`, no dynamic state, no body record
— only a dictionary entry.

`static_templates=1` enables minting in **both** user and system mode (it needs
no region enumeration, so the system/user distinction the sweep forced is
gone). Coverage is **convergent, not eager**: the dictionary fills in as
branches are seen over the run, not all at once at segment open. A branch never
evaluated contributes no alternate (correctly — a consumer never fetches its
untaken side either); a rarely-taken branch's alternate appears the first time
the branch is evaluated. This is a weaker guarantee than the sweep's "every
mapped byte decoded", and an honest one: it matches exactly the fetch space a
mispredict-driven consumer reaches from the branches the workload actually
executed, which is the space that matters.

### Two hook sites

Complementary, covering the two gaps a wrong path alone leaves:

1. **Wrong-path walk** (`wp_commit_bb`, the decomposed `WpStep` pipeline). A
   branch *inside* a wrong-path block resolves one direction (the excursion
   follows its computed successor); its untaken side is never walked, so an
   executed + wrong-path dictionary misses it. The hook mints that side after
   the block is committed. This fills the *deep* gap.

2. **Correct-path seal** (`collect_finalized_bbs`, the PathBuilder seal walk).
   When a branch's wrong-path fork will NOT launch — `wpprune` pruned it,
   wrong-path is disabled (`wp=0`), or paging is off — nothing decodes its
   untaken side, so the seal queues that side for minting once `data_lock` is
   released. When the fork DOES launch, the wrong path itself covers the
   untaken block (and its inner branches feed hook 1), so the seal leaves it.
   The translation-unavail tail — a fork that launched but could not fetch its
   first target — is caught in `emit_finalized_bb` after the walk.

### Depth-N exploration (`static_depth=N`)

The immediate untaken side is only the first block of the never-executed region
a mispredicting front-end wanders into. From each freshly-minted alternate,
the plugin follows its **statically-known successors** recursively up to
`static_depth` levels, minting each never-executed block along the way:

* the architectural **fall-through** — always; and
* a **direct** branch's decoded **target** — both edges of a direct terminator
  are statically known.

An **indirect** terminator (indirect jump/call, return) has no static target,
so that edge ends the chain. The walk is a DFS worklist of `(pc, depth)`
seeded from a fresh mint's successors; it recurses only on blocks a call
actually minted, so the existing-template dedup (`alt_or_bb_covered`) and the
per-segment mint budget bound it and a cycle can never spin (a re-visited PC is
already covered and stops). All of it runs off the hot path — the mint site
already runs after `data_lock` is released, and the successor walk fires only
when a miss was minted, which trends to zero after warm-up.

`static_depth` defaults to **4**, the knee of a coverage/size sweep measured on
`mcf` (user, 50 M window) and a system churn/devio boot (3 M marker window).
Across both, executed- and alternate-fall-through resolution rises steeply
through N≈4 and then flattens while the minted-template count keeps climbing
(roughly doubling from N=4 to N=8) — so N=4 captures the bulk of the reachable
never-executed region at a modest template-section cost, and larger N pays
increasing size for diminishing coverage. `0` mints only the immediate untaken
side (no successor walk).

### Keying, lifetime, and the byte-identity discipline

Alternates live in a segment-scoped `alt_map_`, a sibling of `bb_map_`, keyed by
the same `(asid_root, start_pc)` — kernel VAs to the shared kernel sentinel
bucket, user VAs to the owning process root, via the established VA-domain
classification. Dedup is by construction: a mint whose key is already in
`bb_map_` (executed) or `alt_map_` (minted) is skipped (`alt_or_bb_covered`;
existing wins).

The **body stays byte-identical** to a run with the option off. An alternate
takes a placeholder id at commit and is assigned its real, section-local wire id
lazily by `for_each_alt` at serialization — strictly above every executed id —
so it never consumes an id an executed block would otherwise take; the executed
dictionary numbers exactly as it would with the option off. At serialization an
alternate whose key is shadowed by an executed (`bb_map_`) entry is dropped: the
executed template wins (real id, real profile), and the flag-less alternate
covers only what execution did not reach.

Unlike the retired STATIC template, an alternate carries **no wire flag** (life
`CODE`): it is an ordinary never-executed dictionary entry, indistinguishable on
the wire from any block that happened not to execute — because that is exactly
what it is. The STATIC per-insn flag bit (bit 3) has returned to the reserved
pool; the `insn_flag` vocabulary is unconditionally the historical seven names.

### Guest-read policy, bound, and stats

Guest bytes at an alternate's PC are read with the probing
`qemu_plugin_read_memory_vaddr` (mapped page → decode; unmapped → skipped and
counted), so enumeration never demand-pages or perturbs the guest — the same
valid-mapping policy the wrong path obeys, and the reason a genuinely-unmapped
fall-through is left uncovered (a consumer would fault there too). A per-segment
mint budget (`CST_ALT_MINT_BUDGET`) caps the decode+mint work; the presence test
(one hash lookup per evaluated branch, latched per `bb_tmpl` so a re-walked
block pays it once) is always allowed, and the decode fires only on a miss, so
after warm-up the steady-state cost is one lookup per branch. Reported at exit
(`Branch-alternate minting: ...`): `checks`, `mints`, `depth_mints` (the subset
minted by the successor walk), `skips_unmapped`, `budget_hits`.

### Coverage oracle

`features.wrong_path_coverage` (validator, 4 ISAs) is the teeth. With minting
on, per ISA it asserts: never-executed alternates are minted (`n_static > 0`);
their statically-known successors resolve to template starts
(`alt_succ_res > 0` — the metric `static_depth` drives, since the successor walk
mints those blocks); and never-executed direct-branch targets resolve (BTB
spot-check). The teeth: the minting-off run has **zero** never-executed
coverage (`n_static == 0`), so the on-run's coverage is strictly additive. The
executed conditional-branch fall-through resolution is reported alongside as a
self-consistency figure (it need not be perfect — a fall-through reached only
through a budget-truncated wrong path may legitimately dangle).

---

## Superseded: P1 executable-region sweep (user mode, removed)

The first implementation swept the guest's mapped executable regions at each
segment open — `qemu_plugin_walk_exec_regions` enumerated the PAGE_EXEC ranges
of the linux-user page-flags map, and the plugin linear-decoded them (with
byte-granular resync over data-in-text), minting a never-executed **STATIC**
template per branch-delimited true BB into a `static_map_`. Late mappings (a
`dlopen`'d library, a JIT page) were caught by
`qemu_plugin_register_exec_region_grew_cb`, a hook on linux-user's
mmap/mprotect chokepoint that queued newly-executable ranges for a resweep on
the next correct-path step. STATIC templates carried a dedicated wire flag,
`CST_INSN_FLAG_STATIC`.

It worked, but it was **awkward**: user-mode only (the enumeration had no
system-mode analogue), eager (it decoded the entire executable footprint —
millions of blocks for a large binary — most of which a consumer never
fetches), and it needed two fork plugin-API additions plus a wire flag to carry
templates that minting delivers unmarked. Minting subsumes its coverage goal
convergently and in both modes, so the sweep, its `static_map_`, the
`walk_exec_regions` / `exec_region_grew` APIs, and the STATIC wire bit were all
removed (pre-release, no compatibility owed).

## Superseded: P2 system-mode page-table walk (never built)

The sketched system-mode successor was to enumerate the executable footprint by
walking the page tables of the owned roots (admitting every valid,
executable-permission PTE via a probing read, TLB residency *not* a criterion,
with TLB-fill events as change-notifications for late mappings). It was never
built: opportunistic minting is mode-independent and delivers the same
system-mode never-executed coverage with no enumeration at all, so the
page-table walk is unnecessary. On a `qemu-system-x86_64` virtio-blk
marker-window trace, minting raises executed conditional-branch fall-through
resolution from ~84 % to ~99 %; `static_depth` then deepens coverage of the
minted blocks' own successors.
