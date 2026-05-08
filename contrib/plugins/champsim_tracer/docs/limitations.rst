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
chain is bounded (``wpdepth`` instructions), single-path (no nested
mispredicts beyond the initial one), and discards architectural
register and memory effects at the end of each chain.  This is
sufficient for cache-pollution and prefetcher-training research; it
is *not* sufficient for cycle-level mispredict-penalty modeling or
for studying transient-execution side channels (Spectre / Meltdown
classes) where the precise sequence of speculative micro-ops
matters.

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
graceful workaround exists today; if your workload SMCs heavily,
the trace's templates section will be a snapshot of an early
version of the program text.

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
and other multi-iteration instructions emit one architectural
memop per iteration: the first 16 land in the slotted
``LOAD_ADDR[0..15]`` / ``STORE_ADDR[0..15]`` (and matching ``DATA``
families), and the rest go into one ``EXTRA_LOAD_ADDR`` /
``EXTRA_STORE_ADDR`` raw-vector record per insn.

**WP memops capped at 16 per insn.**  ``MemAccessRecorder::record``
caps WP-side memops at ``CST_FID_SLOT_COUNT == 16`` per
instruction and silently drops the rest.  Real workloads almost
never hit this; pathological cases involve x86 ``rep`` opcodes on
the wrong path, where speculative iteration is bounded by the WP
depth budget anyway.

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

See :ref:`reproducibility` in the quickstart for the full list of
factors that can break byte-stability across runs.  In short:
ASLR, multi-threaded scheduling, and clock-driven guest behavior
are the three usual suspects.

Known issues / footguns
-----------------------

* **The simpoints file format isn't standardized in the docs.**
  The plugin parses ``<interval_id> <cluster_id>`` whitespace-
  separated lines (one per simpoint) plus an optional sibling
  ``.weights`` file.  See :doc:`quickstart` for the format.
* **``GEN_OP_UNKNOWN`` count > 0 in the exit summary is silent.**
  The plugin keeps tracing — the affected instructions appear in
  the trace with opcode = 0, but their classification is missing.
  Run ``champsim_tracer_mnemonic_audit.py`` against a sample trace
  to discover which mnemonics need rows in the per-ISA
  classification table.
* **``thread_id`` resets across segments.**  ``thread_id=0`` in
  segment N is not necessarily the same vCPU as ``thread_id=0`` in
  segment N+1.  Cross-segment vCPU tracking requires correlating
  the per-segment summaries' icount ranges manually.
