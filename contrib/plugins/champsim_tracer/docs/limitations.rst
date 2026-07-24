Limitations
===========

This page collects the things ChampSim Tracer deliberately doesn't do
or doesn't do well.  Reaching for one of these against expectations is
usually a sign you want a different tool, or a documented workaround.

Out-of-scope categories
-----------------------

**Whole-system tracing.**  System-mode tracing is marker-scoped, not
whole-machine.  Each captured process carries a ``(thread_id, asid)``
context; under the default ``policy=latch`` every process that runs
the START marker joins an owned address-space set and is traced —
along with the kernel code it synchronously invokes — until its END
marker, while ``policy=trace-all`` widens the first START to capture
all contexts (see the *System-mode tracing* section of
:doc:`architecture`).  What it deliberately does not cover:
asynchronous-interrupt handling (excluded by default as OS noise
uncorrelated with the workload — though ``interrupts=1`` opts into
tracing it), processes that never run a marker, and the pre-paging
boot path (wrong-path speculation requires the guest MMU to bound
fetches).  Tracing "everything the machine does"
from power-on is not a supported shape.  In user mode, kernel
execution is invisible entirely — system-call boundaries appear as
``GEN_OP_SYSCALL`` instructions and the trace resumes at the
syscall's return.

**Wrong-path simulation in user mode requires an x86 host.**
System-mode wrong-path tracing is portable to every host: speculative
stores are held off real guest memory by the portable
``TLB_FORCE_SLOW`` path on non-x86 backends and by the i386 backend's
``CF_FORCE_SLOW`` inline bypass on x86, which contains them in any
mode.  The single unsupported configuration is user-mode wrong-path
tracing on a non-x86 host, where no softmmu TLB exists to carry the
flag; the plugin detects the gap at its first speculative excursion
and refuses loudly — it aborts rather than ever writing real guest
memory.  See the containment discussion in :doc:`qemu_modifications`.

**Cycle-accurate timing.**  The trace is a *functional* record of
the architectural correct path plus its speculative shadow.  It
does not record cycle counts, IPC, pipeline state, ROB occupancy,
or any other timing artifact.  Timing models live in the consumer
simulator (ChampSim, gem5, etc.); the tracer hands them the inputs.

**Real speculative-execution semantics in detail.**  The wrong-path
chain is bounded (``wpdepth`` instructions), and single-path (no nested
mispredicts beyond the initial one). This is sufficient for cache-pollution
and prefetcher-training research; it may not be sufficient for studying 
transient-execution side channels (Spectre / Meltdown classes) where the 
precise sequence of back-to-back mispredictions matters.

Workload-shape limitations
--------------------------

**Forking and multi-process workloads.**  Untested.  ``fork()``
under user-mode QEMU produces a host child process; whether and
how the plugin loads in the child depends on QEMU's plugin-API
internals, and the resulting traces have not been validated.  A
trace from a forking workload should be treated as best-effort
until the body stream is confirmed to cover the path of interest.

**Self-modifying code (SMC).**  Self-modifying code is traced, not
refused.  When the correct path re-executes a basic block whose
committed template holds different bytes — an in-place patch that
preserves the block's instruction boundaries, the canonical inline-
cache / call-target / boot-time alternatives shape — the plugin mints
a new template *revision*: a fresh ``template_id`` at the same
``start_pc``, keyed internally by ``(asid_root, start_pc)``.  The
superseded revision is retained and serialised alongside its
successor, and every body entry references the ``template_id`` that
was live when it executed, so the version timeline is implicit in the
body's own references (see :ref:`poison-detection` for the detector
seam and the consumer contract in ``format.rst``).

Two properties keep this bounded.  Writes to code that is never
re-executed never surface (no re-translation, no revision — a region
written many times and entered once mints exactly one revision, the
state at execution).  A mutation that *returns* to a previously-seen
state reuses that state's original ``template_id`` via a content
signature, so A/B/A/B call-target patching resolves to the two
distinct states rather than an unbounded transition count.  A per-PC
cap (``smc_revisions=N``, default 1024) is a backstop *bug detector*,
not a fidelity budget: no legitimate SMC pattern approaches it, so
crossing it — a false-mutation loop or a pathological JIT — stops
minting, keeps the body referencing the last revision (decoded bytes
at that pc become approximate from there), and emits a loud
once-per-segment stderr warning plus an ``SMC revision overflow
events`` line in the exit-time statistics report.

Revisions mint **only** from correct-path-confirmed translations.  A
wrong-path speculative translation that observes mid-write bytes never
versions a template (it reuses the live one), and neither does the
first correct-path confirmation of a block only the wrong path had
seeded — the same guard that keeps speculative mis-stamps out of the
dictionary.  The remaining hard edge is a patch that changes the
block's instruction *boundaries* (different insn PCs, not just bytes):
that is treated as shape divergence rather than an in-place revision,
and the original template is kept.

Hard bounds at a glance
-----------------------

The wire format and the speculative simulator carry a small set of
fixed numeric ceilings.  Most workloads never approach them, but
programs with unusual shape (very wide vector memops, register-sized
bulk memory instructions, deep wrong-path divergence) can.  Each row
links to the prose that explains the consequence of hitting it.

.. list-table::
   :header-rows: 1
   :widths: 30 18 52

   * - Quantity
     - Bound
     - Notes
   * - Instructions per basic block
     - no fixed cap
     - A true BB runs from a branch target to the next branch; the
       only limit is host memory for the template.  Templates grow
       with BB length.
   * - Instructions per trace
     - no fixed cap
     - Bounded only by the 64-bit body-entry counter and available
       trace storage.  ``total_target_insns = 0`` in the header means
       "no preset length"; count body entries via the trailer's
       ``num_entries`` instead.
   * - Slotted load addresses / data per instruction
     - ``CST_FID_SLOT_COUNT`` = 64
     - ``LOAD_ADDR``/``LOAD_DATA`` slots 0..63.  There is no
       overflow vector; a single instruction issuing more than 64
       loads is not representable (no supported ISA instruction
       does — AVX-512 gather is 16-wide).
   * - Slotted store addresses / data per instruction
     - ``CST_FID_SLOT_COUNT`` = 64
     - ``STORE_ADDR``/``STORE_DATA`` slots 0..63; likewise no
       overflow vector.
   * - WP-side memops captured per instruction
     - ``CST_FID_SLOT_COUNT`` = 64
     - ``MemAccessRecorder::record`` drops memops past this on the
       wrong path (no overflow vector on WP).
   * - Load/store data value width
     - ``CST_MAX_WIDE_BYTES`` = 64 bytes (512 bit)
     - A single memory value is encoded in at most 64 bytes.
   * - Register snapshot width
     - ``CST_MAX_WIDE_BYTES`` = 64 bytes (512 bit)
     - ``regdata=1`` copies at most 64 bytes per architectural
       register; wider state is truncated to the low 512 bits.
   * - Distinct architectural register IDs
     - 255 (``GenericRegId`` 0..254)
     - 255 (``REG_ID_COUNT``) is the count sentinel; an ISA needing
       more than 255 register IDs requires a wire-format change.
   * - Stuck-PC speculative-loop guard
     - 64 same-PC iterations (reuses ``CST_FID_SLOT_COUNT``)
     - A wrong-path instruction that never advances PC (e.g. an x86
       ``rep`` whose sandboxed write keeps PC anchored) is forced
       past once the same-PC iteration count *exceeds* 64.  The 64
       threshold is a reuse of ``CST_FID_SLOT_COUNT`` for
       convenience, not an independently tuned bound.
   * - Wrong-path chain depth
     - ``wpdepth`` instructions (configurable)
     - The speculative side-trip after each correct-path branch is
       bounded by the ``wpdepth`` plugin argument.

The rows below expand the consequences that are not self-evident
from the table.

QEMU base bounds
----------------

Two ceilings the wrong-path simulator inherits are not tracer
constants — they live in this repository's modified QEMU base, not in
the plugin.  They are listed here because they shape what the WP chain
can record, but fixing or tuning them is a QEMU-fork change, not a
plugin change.

.. list-table::
   :header-rows: 1
   :widths: 30 18 52

   * - Quantity
     - Bound
     - Notes
   * - WP speculative store buffer
     - ``PLUGIN_SPEC_STORE_BUF_MAX`` = 64 MiB of byte entries
     - The per-CPU speculative store buffer (QEMU's
       ``qemu_plugin_spec_mode_begin`` / ``_end`` API) holds every
       wrong-path write for store-to-load forwarding and discards
       them all at chain end.  Past the cap no new keys are added
       (existing keys still update); excess speculative stores are
       not forwarded.  Far above any real wrong-path store set.  The
       constant is defined in the modified QEMU base at
       ``accel/tcg/internal-common.h``.
   * - AArch64 FEAT_MOPS speculative set/copy
     - ``MOPS_SPEC_MAX_BYTES`` = 256 bytes per instruction
     - ``SETP/SETM/SETE`` and ``CPYP/CPYM/CPYE`` loop a
       register-sized memory op inside one TCG helper.  On the wrong
       path the size register is speculative garbage, so the QEMU
       fork clamps the operation to a sub-page speculative-execution
       bound (wrong-path memory is discarded, so a bounded set/copy
       is indistinguishable).  Both the constant and the clamp logic
       live in the modified QEMU base at
       ``target/arm/tcg/helper-a64.c``; the plugin contains no MOPS
       handling of its own.

Trace-content limitations
-------------------------

**Wide register snapshots are 512-bit-capped.**  ``regdata=1``
copies up to 64 bytes of each architectural register into the
snapshot.  This covers SSE / AVX / AVX-512 ZMM (512 bits), AArch64
SVE up to a 512-bit vector length, and RISC-V V at moderate VLEN
settings.  Larger architectural states (1024-bit-VLEN SVE,
RVV at VLEN=2048, AMX tile registers) are truncated to the first
512 bits.  Tile-register support requires producer-side work
beyond the wire format's current shape.

**Memory-data values are 512-bit-capped.**  Same width budget; a
single load/store value is encoded in up to 64 bytes.  ``rep movs``
and other multi-iteration instructions surface one body entry per
iteration (see the wire-format spec's *REP-prefixed self-loop BBs*
section), so each entry carries at most 1 load + 1 store — the
slotted ``LOAD_ADDR[0..63]`` / ``STORE_ADDR[0..63]`` (and matching
``DATA``) families cover every supported instruction; there is no
overflow vector, and the widest single-instruction memops (AVX-512
gather/scatter, 16-wide) sit well inside the 64 slots.

**Memops capped at 64 per insn.**  ``MemAccessRecorder::record``
caps per-instruction memops at ``CST_FID_SLOT_COUNT`` = 64 and
drops the rest.  Real workloads almost never hit this;
pathological cases involve x86 ``rep`` opcodes on the wrong path,
where speculative iteration is bounded by the WP depth budget
anyway.

**Sub-instruction WP coverage past faults is limited.**  The WP
simulator continues *past* in-flight faults on non-branch
instructions to preserve the "BBs always end in a branch"
invariant.  But syscall-style branches that fault terminate the
WP chain — speculative state past the syscall is not modeled.

**``total_target_insns = 0`` means "unbounded".**  Non-simpoint
runs without an explicit ``stop=`` set the header field to zero.
Consumers that need a length-of-trace number must count body
entries; the trailer's ``num_entries`` field is authoritative for
that.

**Physical-page and disk-I/O records are system-mode only.**
``physaddr=1`` adds each memop's physical-page base
(``CST_FID_LOAD_PPAGE`` / ``STORE_PPAGE``, rebuilt as
``ppage | (vaddr & 0xFFF)``), and ``devio=1`` — on by default —
brackets disk requests with ``DEVIO_START`` / ``DEVIO_STOP`` records.
Both depend on the guest MMU and the block backend, so both are inert
in user mode: a user-mode trace carries neither and is byte-identical
regardless of the options.

**Disk-I/O owner attribution is exact only under a specific virtio
configuration.**  A ``DEVIO_START`` record carries an *exact*
``(owner_thread_id, owner_asid)`` only when the guest's virtqueue kick
is observable in vCPU context — a ``virtio-blk`` device run with
``ioeventfd=off`` and no dedicated iothread.  Under the default virtio
ioeventfd fast path, a non-virtio device (IDE/AHCI), or kernel-internal
I/O, the record falls back to *positional* attribution (the
``(asid, thread)`` context in force at its stream position) — correct
for a single marked process, a guess once two processes' disk I/O
interleaves in the same body stream.  Multi-process exact attribution
additionally requires each traced process pinned to its own vCPU: the
captured owner comes from the same per-vCPU kernel-mode ownership model
every kernel basic block uses, which has no clean answer once the guest
scheduler migrates a process mid-syscall.  See the *Disk-I/O records*
recipe in :doc:`quickstart` for the canonical invocation.

**Never-executed template coverage (``static_templates=1``) is
convergent, not exhaustive.**  When enabled (off by default, both
modes), the plugin mints the untaken side of a branch as a
dictionary-only template the first time that branch is evaluated by
the correct path or a wrong-path excursion — it does not enumerate the
binary's mapped executable footprint up front.  Coverage therefore
accumulates over the run: a branch the workload never evaluates
contributes no alternate, and a rarely-taken branch's alternate appears
only once that branch is finally evaluated.  This matches exactly the
fetch space a mispredict-driven consumer reaches from the branches the
workload actually executes, but it will under-cover a consumer that
wants every reachable instruction decoded from a cold start.
``static_depth=N`` (default 4) extends each freshly-minted alternate
along its statically-known successors — the fall-through always, and a
direct branch's decoded target — to widen coverage per mint; an
indirect terminator (indirect jump/call, return) has no static target,
so that edge ends the walk.

**Marker injection covers the tracer's four target ISAs, on Linux
guests only.**  A workload with no compiled-in marker is traced by
running it under :program:`cst_attach`, which pokes the marker into
the target's entry point over ``ptrace``.  That is guest-side code, so
it needs a per-guest backend: Linux backends exist for x86/x86-64,
AArch64, RV64 and **little-endian** 32-bit MIPS.  Big-endian MIPS is
excluded because the shared marker encoder emits a little-endian
instruction stream, and a non-Linux guest would need a different debug
API entirely (Windows debug API, macOS Mach, BSD ``ptrace``).  On an
uncovered host/arch pair :program:`cst_attach` refuses to run rather
than injecting bytes that would decode as something else.  A workload
that can be rebuilt does not need the injector at all — a compiled-in
marker works on every ISA the tracer targets.

**A marker window held open by a dead process closes only at the
icount budget.**  Under ``policy=latch`` a process that exits without
running its END marker leaves its window open until the segment's
icount budget elapses.  ``latch_timeout=<ms>`` is the opt-in backstop
— it closes a window idle for longer than the given wall-clock
interval — but it is off by default because idleness alone cannot
distinguish a dead process from a merely long-blocked live one.

Reproducibility caveats
-----------------------

See :ref:`reproducibility` in the quickstart for the recommended
invocation recipe that controls the major byte-stability
breakers (ASLR, kernel-supplied randomness, host scheduling,
inherited environment).  One residual non-determinism source
deserves its own treatment here because it is fundamentally not
fixable from the plugin side:

**Traces are not bit-deterministic.**  Even with every
controllable randomness source pinned (``-seed N`` for
``AT_RANDOM``, ``env -i`` for the inherited environment,
``setarch -R`` for host ASLR, ``taskset -c 0`` for host
scheduling), body records vary slightly run-to-run.
The residue manifests as a small fluctuation in load-address,
load-data, store-data, destination-register snapshots,
and basic-block execution counts.

**Why it happens.**  The wrong-path simulator may occassional
stumble into data bytes and decode them as instructions, which
is normal speculative behaviour but non-deterministic because the
data bytes can change between runs.  When this happens, the WP
chain diverges and the trace captures a different sequence of
events. In addition, startup behavior of the program 
(e.g., dynamic loader decisions, heap layout) can differ 
between runs and cause different instruction sequences
to be executed, which also leads to non-deterministic traces.

**Adjacent invariant: true-BB SHAPES *are* deterministic.**  A
separate flavour of WP non-determinism — multiple distinct
"true-BB" shapes committed at the same ``start_pc`` because the
speculator wandered into stack / heap / data and decoded *bytes*
as "instructions" — is handled.  The translation-time
poison detector (see :ref:`poison-detection` in the architecture
doc) catches Capstone decode failures before any divergent fragment
can reach the chain assembler, and revision minting is gated to
correct-path-confirmed translations, so a speculative wander never
adds a template.  The BB cache therefore stays canonical regardless
of which WP path discovers a given ``start_pc``.  The residual
byte-level non-determinism above is data-only (load values, store
values, register snapshots) and operates over *real, decoded code* —
the BB shapes themselves are stable.  The one deliberate exception is
correct-path self-modifying code, which mints a byte-distinct
*revision* at the same ``start_pc`` on purpose (see **Self-modifying
code** above); those revisions are still deterministic — one per
distinct executed state — and are distinguished on the wire by
``template_id``, not by ``start_pc``.
