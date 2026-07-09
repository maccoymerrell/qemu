Limitations
===========

This page collects the things ChampSim Tracer deliberately doesn't do
or doesn't do well.  Reaching for one of these against expectations is
usually a sign you want a different tool, or a documented workaround.

Out-of-scope categories
-----------------------

**Whole-system tracing.**  System-mode tracing is process-pinned: a
guest-issued marker opens the window and pins it to one address
space, and the trace covers that process plus the kernel code it
synchronously invokes (see the *System-mode tracing* section of
:doc:`architecture`).  What it deliberately does not cover:
asynchronous-interrupt handling (excluded by design — OS noise
uncorrelated with the workload), other processes, and the
pre-paging boot path (wrong-path speculation requires the guest MMU
to bound fetches).  Tracing "everything the machine does" is not a
supported shape.  In user mode, kernel execution is invisible
entirely — system-call boundaries appear as ``GEN_OP_SYSCALL``
instructions and the trace resumes at the syscall's return.

**Wrong-path simulation requires an x86 host.**  The spec-mode
slow-path routing flag (``CF_FORCE_SLOW``) is implemented in the
i386 TCG backend only, which serves x86 and x86-64 *hosts* (guest
ISA coverage is unaffected).  On another host architecture,
wrong-path stores would reach real guest memory, so wrong-path
simulation is unsafe to enable there; see the porting note in
:doc:`qemu_modifications`.

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

**Self-modifying code (SMC).**  Translation-time poison detection
(see :ref:`poison-detection` in the architecture doc) catches both
the *real* SMC case and the *wrong-path-into-data* case at the
fragment-creation boundary.  Two stability signals are checked on
every canonical insn before the splitter materializes a fragment:
a Capstone decode failure, and a 4-byte-instruction-word change
against the first sighting at that PC.  Either signal poisons the
TB's ``start_pc``; the fragment is not created, the WP walker
refuses to re-enter that PC, and (only when the poisoned PC is
inside the main binary's text segment) the plugin emits a one-shot
SMC-suspect warning to stderr.  Workloads that genuinely modify
their own code (JIT compilers replacing trace fragments, dynamic
patchers) will surface that warning and lose later behaviour at the
modified addresses — the templates section snapshots the first-seen
program text at each ``start_pc``.  Out-of-text-segment poisoning
fires silently because the symptom is "WP wrong-pathed into data,"
which is normal speculative behaviour the tracer just refuses to
record.

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
doc) catches both Capstone decode failures and
bytes-changed-since-first-sighting before any divergent fragment
can reach the chain assembler, so the BB cache stays canonical
regardless of which WP path discovers a given ``start_pc``.  The
residual byte-level non-determinism above is data-only (load
values, store values, register snapshots) and operates over
*real, decoded code* — the BB shapes themselves are stable.
