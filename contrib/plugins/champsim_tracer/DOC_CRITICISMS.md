# Documentation criticisms

A critical pass over the docs as a researcher would read them.  Each
item names what's missing, why it matters for someone using the
tracer for cache / branch / prefetcher work, and where the fix
landed.  When you find yourself surprised by tracer behavior or
unable to answer a basic question from the docs, the answer should
be on this page (or, ideally, gone — the doc gap that prompted the
entry should be closed).

The fixes are recorded as `Fix:` lines under each criticism.  The
goal of keeping this file in-tree is that future changes to the
tracer can use it as a checklist: did the change introduce any new
gaps that need documentation?

## 1.  No "what does this tool actually produce, and why" page for new readers

A first-time researcher landing on the docs gets a one-paragraph
summary on the index page, a build/run quickstart, and then is
dropped straight into the wire format and the architecture.  There
is no pass at the layer in between: *what is a `.cst` trace,
qualitatively, and what kinds of research questions can it answer?*

Specifically, the docs don't say:

- That a `.cst` is a per-segment basic-block-granularity execution
  trace with optional dynamic operand data.
- That the wrong-path stream models the architectural effects a
  branch-mispredicting machine *would have produced*, useful for
  cache-pollution and prefetcher-training research.
- That the templates section is a deduplicated dictionary of every
  static basic block the program executed; consumers can derive
  per-instruction PC, opcode, registers without inspecting the
  body stream.

Without this framing a reader reasonably concludes the trace is "an
instruction stream" and is then confused by the templates / body
split, the WP chain semantics, and why memory addresses and register
values are emitted as field-deltas rather than per-instruction
records.

Fix: rewrite the index page's intro to say what the trace *is* and
what research questions it's good for, before pointing at the
quickstart.  Cross-link a new "what's in a trace" overview from the
quickstart and the format spec.

## 2.  No performance / overhead numbers anywhere

A researcher running a long workload (e.g. a 100 G-instruction SPEC
run) can't make basic capacity-planning decisions from the current
docs:

- What's the runtime slowdown vs native QEMU at each capture-flag
  setting?
- How big does the trace get per architectural instruction (bytes
  per insn) under typical configurations?
- What fraction of runtime is the WP simulator vs CP attribution vs
  body encoding?
- How much memory does the plugin itself use?

The docs allude to "WP runtime drops considerably (typically 2-3×)"
in passing but never give absolute baselines or trace-size numbers,
and only the audit doc hints at the byte-budget structure.

Fix: add a "Performance and overhead" section to the architecture
page with measured numbers (slowdown, bytes-per-insn, peak RSS) for
the common configurations on a representative SPEC-class workload
plus the rules of thumb that follow (WP doubles size, mem-data
doubles size again on memory-bound code, etc.).  Also note the
mitigations users already have (the `outpipe=` zstd recipe, simpoint
mode, dropping `wp_memdata`).

## 3.  Multi-threaded / multi-vCPU semantics are barely mentioned

`BODY_TAG_THREAD_SWITCH` shows up in the wire format and the
quickstart mentions QEMU vCPUs in passing, but the docs don't answer
what a researcher actually needs to know:

- Is the body stream a serialized interleaving of all vCPUs' BBs in
  execution order, or a per-vCPU stream concatenation?
- What does `thread_id` mean numerically?  Is it the QEMU vCPU
  index?  A monotonic counter?  Does it survive across segments?
- What's the semantics of `icount` when multiple vCPUs are active?
  Is the trace a cross-product or per-vCPU?
- Does `exec_lock` serialization mean the trace is single-threaded
  even for an SMP guest workload?

This matters for any researcher trying to use the tracer on a
multi-threaded application — both whether their workload is
representable and how to interpret the resulting trace.

Fix: add a "Multi-vCPU semantics" section to the architecture page
that answers all four questions explicitly, and note the limitations
in the "Limitations" page (criticism 8 below).

## 4.  Determinism and reproducibility guarantees aren't stated

For research repeatability:

- Is the same binary + same command line + same trace flags
  guaranteed to produce a byte-identical trace across runs?  Across
  hosts?  Across QEMU versions?
- What about ASLR?  Is the plugin's `start_pc` field a virtual
  address that depends on randomization?
- Is the WP target choice deterministic given the same execution
  history?

The architecture doc's caveats list mentions a few subtle
deterministic-ordering points (TB-cache-keyed translations, BB
cache survival across segments) but never frames "this trace is
deterministic" as a property a researcher can rely on.

Fix: add a "Reproducibility" section to architecture (or quickstart
under "Running the tracer") covering ASLR, host-CPU effects,
QEMU-version stability, and the trace's deterministic vs non-
deterministic content.

## 5.  No "use case → flag combination" recipe table

The quickstart documents every flag individually but never groups
them by research goal.  Three common cases the docs should answer
in one place:

- "I want to feed ChampSim a cache-and-prefetcher trace": which
  flags?
- "I want a branch-prediction trace": which flags?  Should I keep
  WP on?  Memory data?
- "I want a value-prediction trace": ?

A user running for the first time has to read the entire flag
catalog and reason about it.

Fix: add a "Common configurations" subsection to the quickstart
with named recipes, each a one-line invocation plus a one-paragraph
rationale.

## 6.  ChampSim consumer guidance is missing despite the project's name

The project is named "ChampSim Tracer" and the index says it's for
ChampSim, but nothing in the docs covers how to actually feed a
`.cst` trace into ChampSim.  Specifically:

- Does ChampSim consume `.cst` directly, or does there need to be
  a converter?
- What's the recommended ChampSim trace format ChampSim wants?
  (ChampSim historically uses an `instr_t`-shaped binary trace.)
- Where does the per-instruction memory address data go?

A reader could reasonably expect at least a "see this companion
project" link.

Fix: add a "Feeding ChampSim" section to the quickstart pointing at
the companion converter (or, if none exists, documenting the gap
and the rough shape of the conversion task).

## 7.  Build prerequisites are vague

"Capstone is required" plus an `--enable-plugins` flag is not enough
for someone who'd rather not chase `meson` errors.  Missing:

- Minimum QEMU version (we're on a fork — what's the upstream base
  this synced from?)
- gcc/clang version
- glib version
- What's the actual `./configure` invocation that produces a usable
  build dir, with or without softmmu targets?
- Is `--target-list=...` recommended to avoid building targets the
  tracer doesn't need?

Fix: expand the quickstart's build section with a concrete tested
configuration (Ubuntu 24.04 / Debian 13, gcc 13, glib 2.78), the
exact `./configure` line, and a note about which target lists work.

## 8.  No "Limitations" page

Multiple non-obvious behaviors live as caveats inside architecture
or in throwaway phrases scattered across other pages.  A new user
will keep tripping over them:

- User-mode QEMU only; no system-mode support is built or tested.
- Forking workloads: the plugin observes the parent's vCPU only
  (or, more carefully, what does QEMU's plugin API expose to a
  forking process?).
- Self-modifying code: the SMC warning in `commit_true_bb` is the
  only signal; the trace will silently use the first observed
  template otherwise.
- JIT'd code (V8, JVM, Python with C extensions): whether the
  generated machine code lands in the trace or not.
- `dlopen` and dynamic linking: probably handled, but undocumented.
- vDSO: undocumented.
- Sub-instruction WP coverage: WP entries don't run past faults
  in v1.9 except into syscall-style branches.
- `total_target_insns = 0` (unbounded) means consumers must
  *count* body entries to know the trace length.

Fix: add a `limitations.rst` page collecting these in one place,
each with a one-paragraph "what happens" and (where applicable)
"workaround".

## 9.  ISA support matrix gives top-level coverage but not extension support

The index says "x86_64, aarch64, riscv64, mipsel" but doesn't say
*which subsets*.  Researchers studying:

- AVX-512 mask register usage on x86 — supported?  Captured?
- SVE on AArch64 — supported?  Vector-length aware?
- RVV (RISC-V V extension) — covered?  What about mixed RVC+RVV?
- MIPS DSP / MSA extensions — covered?

The reference page hints at predicate registers and vector
registers existing in the generic-id space, but never says which
ISAs actually emit them.

Fix: add an "ISA coverage" table to the reference page (or a new
dedicated page) listing per-ISA: supported extensions, captured
register width, known unclassified instruction families, and the
dependency on Capstone's coverage.

## 10.  No license / citation guidance

For a research tool the license and citation expectations should be
visible in the docs, not left implicit in source headers.

- License (GPL-2.0-or-later) — in source headers but not
  user-facing.
- How to cite if used in a paper.
- Acknowledgement to upstream QEMU and Capstone.

Fix: add a one-page "License and citation" section to the index or
as a final appendix.

## 11.  Wrong-path semantics: the *why* is missing from user-facing docs

The architecture page describes *how* WP simulation works in detail,
but a researcher reading the user-facing pages doesn't get the
*why*:

- WP traces let consumers model speculation-induced cache pollution
  (Spectre research, prefetcher-evaluation work).
- They model what a real machine *would have* done if its predictor
  guessed wrong.
- They are *not* a complete model of speculative execution: the WP
  shadow is bounded, single-path (no branch nesting beyond the
  initial mispredict), and discards architectural effects.

Without this, users mistakenly think enabling `wp=1` is a complete
speculation model.

Fix: add a "Wrong-path simulation" subsection to the quickstart
that frames the model and its limits in one paragraph each, before
the user reaches the per-flag detail.

## 12.  No FAQ / troubleshooting page

Common failure modes have no one-stop documentation:

- "Why does my trace contain `GEN_OP_UNKNOWN`?" → mnemonic table
  miss.
- "Why is my trace 100 GB?" → wp + memdata on a memory-heavy run.
- "Why does the segment summary say `wp_simulations skipped =
  N`?" → branches the WP target resolver couldn't classify.
- "The plugin aborted with `unknown option: foo` — why?"
- "I'm getting `no valid simpoints` — what format does the spfile
  want?"

Fix: add a `troubleshooting.rst` page with these in question/answer
form and link from the index.

## 13.  Wire-format docs don't tell the user what a trace decode-runs *is*

`champsim_tracer_format.md` documents the byte-level encoding but
never says, for a non-format-author reader, what they get out of the
decoder for one body entry.  The conceptual content of "one body
entry = one true basic block invocation, plus its WP chain, plus
all dynamic memops and dst register snapshots that happened during
that BB" is implicit in the wire format but never spelled out as
a sentence.

Fix: add a "What a body entry represents" paragraph to the format
doc near the top of section 4, before the byte-level layout.

## 14.  Trace validation workflow is buried

The IFRAME mechanism is documented in three places (caveats,
architecture, format spec) but nothing tells a user "here's how to
validate that a freshly produced trace round-trips correctly."

Fix: add a "Validating a trace" section in the decoder doc covering
the IFRAME approach plus the byte-budget audit's role as a sanity
check.
