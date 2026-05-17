Limitations
===========

This page collects the things ChampSim Tracer deliberately doesn't do
or doesn't do well.  Reaching for one of these against expectations is
usually a sign you want a different tool, or a documented workaround.

Out-of-scope categories
-----------------------

**System-mode emulation.**  The plugin is built and tested against
QEMU's user-mode emulators (``qemu-x86_64``, ``qemu-aarch64`` etc.).
It runs only against user-space binaries; system-call boundaries
appear in the trace as ``GEN_OP_SYSCALL`` instructions, but the
trace ends at the syscall — kernel execution is not captured.  If
you need kernel-mode visibility, a system-mode plugin or a different
infrastructure is required.

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
internals and we haven't validated the resulting traces.  If your
workload forks, treat the trace from that run as best-effort
until you've confirmed the body stream covers the path you care
about.

**Self-modifying code (SMC).**  The plugin emits a one-shot
"differing insn sequence" warning to stderr when ``commit_true_bb``
sees a true BB at a known ``start_pc`` whose instruction sequence
no longer matches the cache.  After the warning, the plugin keeps
using the *first* observed template — newer instructions at that
PC are ignored.  Workloads that genuinely modify their own code
(JIT compilers replacing trace fragments, dynamic patchers) will
produce traces that under-describe their later behavior.  No
graceful workaround exists; if your workload SMCs heavily,
the trace's templates section is a snapshot of the first-seen
program text at each ``start_pc``.

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
     - effectively unbounded
     - A true BB runs from a branch target to the next branch; no
       fixed cap.  Templates grow with BB length.
   * - Instructions per trace
     - effectively unbounded
     - ``total_target_insns = 0`` in the header means "unbounded";
       count body entries via the trailer's ``num_entries`` instead.
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
   * - WP speculative store buffer
     - ``PLUGIN_SPEC_STORE_BUF_MAX`` = 64 MiB of byte entries
     - The per-CPU speculative store buffer (QEMU's
       ``qemu_plugin_spec_mode_begin`` / ``_end`` API) holds every
       wrong-path write for store-to-load forwarding and discards
       them all at chain end.  Past the cap no new keys are added
       (existing keys still update); excess speculative stores are
       not forwarded.  Far above any real wrong-path store set.
   * - AArch64 FEAT_MOPS speculative set/copy
     - ``MOPS_SPEC_MAX_BYTES`` = 256 bytes per instruction
     - ``SETP/SETM/SETE`` and ``CPYP/CPYM/CPYE`` loop a
       register-sized memory op inside one TCG helper.  On the
       wrong path the size register is speculative garbage, so the
       operation is clamped to a sub-page bound (wrong-path memory
       is discarded, so a bounded set/copy is indistinguishable).
   * - Stuck-PC speculative-loop guard
     - ``CST_FID_SLOT_COUNT`` = 64 same-PC iterations
     - A wrong-path instruction that never advances PC (e.g. an x86
       ``rep`` whose sandboxed write keeps PC anchored) is forced
       past after this many same-PC iterations, preventing an
       infinite speculative loop.
   * - Wrong-path chain depth
     - ``wpdepth`` instructions (configurable)
     - The speculative side-trip after each correct-path branch is
       bounded by the ``wpdepth`` plugin argument.

The rows below expand the consequences that are not self-evident
from the table.

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

**WP traces are not bit-deterministic.**  Even with every
controllable randomness source pinned (``-seed N`` for
``AT_RANDOM``, ``env -i`` for the inherited environment,
``setarch -R`` for host ASLR, ``taskset -c 0`` for host
scheduling), wrong-path body records vary slightly run-to-run.
The residue manifests as a small fluctuation in load-address,
load-data, store-data, and destination-register snapshot counts
between two stable patterns the run can fall into.  Aggregate
counts (entries, total instructions, address-set coverage)
remain reproducible.

**Why it happens.**  The wrong-path simulator follows branch
directions the program would not normally take.  Correct-path
code typically initialises memory before reading it, but the
wrong-path can leap past the initialisation step (because its
predicate evaluated the other way) and dereference a stack
frame or a malloc chunk while it still holds residue from a
prior function call.  The bytes at those addresses are
whatever the OS, glibc, or a previously-returned function left
behind — they are not "random" in any cryptographic sense, but
they are not bound by the program's data-flow either.  When a
WP load reads such an address, the value flows into the next
instruction; if that instruction is a comparison feeding a
conditional branch, the WP simulator follows different
downstream paths in different runs.  The bistable pattern
observed in practice corresponds to a single such comparison
landing on each side of its threshold in different runs.

**Why we can't fix it.**  Detecting the read of uninitialised
data would require MSan-style shadow-memory tracking (one bit
per byte of guest memory marking whether CP code has ever
written it) plus a policy decision on what to substitute when
WP reads an unwritten byte.  Neither the shadow tracking nor
the substitution policy fits within the plugin's "record what
QEMU executed" architecture without significant overhead and
behavioural changes that would themselves be a research
contribution.

**What it doesn't affect.**  Aggregate WP counts (entries,
total instructions, branch outcomes, store-address coverage)
are reproducible.  Cache-pollution, prefetcher-training, and
branch-predictor-training studies that aggregate over WP
records are not perturbed.  Studies that need an exact
byte-stable WP record stream (e.g., comparing two trace
decoders, validating an encoder change) should diff CP-only or
use ``wp=0``.
