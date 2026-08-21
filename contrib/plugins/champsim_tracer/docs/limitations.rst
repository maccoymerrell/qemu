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
the START marker latches its marker vaddr as a window and is traced —
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
committed template holds different bytes — an inline-cache or
call-target patch, a boot-time alternative, a JIT re-emission — the
plugin mints a new template *revision*: a fresh ``template_id`` at the same
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
dictionary.

Revision minting is **shape-agnostic**.  A rewrite is detected by
comparing the overlapping prefix of the committed template and the
freshly-assembled block — the first ``min(old, new)`` instructions, at
PC-aligned positions — so a byte difference anywhere in that overlap
mints a revision whatever the new block's shape is: an in-place patch
that preserves the instruction boundaries, a rewrite that *moves* them
(kernel alternatives and static-key patching, JIT re-emission), or one
that changes the instruction count outright.  A revision is only ever a
new ``template_id``, and the wire represents that identically for any
shape, so nothing about the block's new layout constrains it.  Because
a template's byte image is a zero-padded fixed-stride copy of each
instruction's real bytes, an instruction whose *length* changed can
never compare equal to the one previously recorded at its PC, so the
prefix comparison detects a boundary move at the position where it
begins.

The one difference that does **not** mint is an *extent-only* one: the
overlapping instructions agree byte for byte and only the block's
length differs, meaning the same code was assembled over a different
run of itself — a chain sealed at a different terminator, a page-split
fragment, a chain force-committed by the fault machinery.  That is an
assembly artifact rather than a code change; the committed template is
kept, a once-per-run explanatory note goes to stderr, and the event is
counted in the ``SMC extent-only artifacts`` statistic.

.. _wp-wall-clock-cost:

Wall-clock cost of the wrong-path walker
----------------------------------------

The wrong-path walker is the dominant consumer of a traced vCPU's host
wall clock, and by a wide margin.  **This is a bound on how long a
capture takes, and on nothing else.**  It is not a fidelity bound —
nothing about the trace's content depends on it — and, as the next
paragraph establishes, it is not a bound on anything the guest can
observe either.  It is documented so a run can be sized, not so a
symptom can be explained by it.

.. _wp-time-transparency:

**The guest cannot see this time at all.**  An excursion runs with the
guest's virtual clock frozen (``qemu_plugin_spec_vtime_pause``), and the
matching resume *discards* the interval the excursion consumed, so the
guest's architected counters read the same value after an excursion as
before it — the clock is put back where it stood when the excursion
started.  Correct-path instrumentation runs under the same freeze
(``VClockPauseGuard``).  The design intent is absolute: an arbitrarily
long wrong path must have zero guest-visible effect, so that the depth
of speculation is free to be a modelling choice rather than a budget.
Every wrong-path state instrument — interrupts lost or gained across the
excursion, timer counters, device state, register rollback — reads zero
throughout, correctly, because nothing is corrupt.

The one qualification is scope: the freeze is a system-mode mechanism
and a no-op under user-mode emulation, where there is no guest virtual
clock to freeze and a guest that reads a clock reads the host's.

**What follows for diagnosis, and it is the useful part.**  Because no
guest-visible time passes on the wrong path, host time spent there
cannot be the reason a guest stopped making architectural progress.  So
if a guest progresses under ``wp=0`` and does not under ``wp=1``, the
difference is *state*, not *time*: something the excursion changed and
the restore did not put back.  Hunt the restore — the per-target
``TCGCPUOps::spec_clock_resync`` hook, the register and device rollback,
the interrupt-line reconciliation — and not the cost.  The figures below
will not tell you anything about such a case; they will only tell you
what the capture cost.

**How large that cost is.**  Measured on x86-64, one vCPU,
``wp=1 wpdepth=64``, with the instrument described below: wrong-path
excursions hold roughly **half of the vCPU thread's host wall clock** —
median 0.53 on a user-mode static binary and 0.52 (peak 0.72) on a
system-mode marker capture.  The same user-mode workload traced with
``wp=0`` completes in 1.33 s against 7.76 s with ``wp=1``: the walker is
a 5.8x multiplier on total capture time at the default depth.  Cost
rises with ``wpdepth`` and with anything that shortens translation
blocks (a small ``-accel tcg,tb-size=`` forces more speculative
dispatches per excursion).

That fraction is also remarkably insensitive to configuration — median
0.428 to 0.578 across six system cells (2,138 sampler windows), because
correct-path cost scales with ``wpdepth`` alongside it.  What does scale
is the size of a single excursion:

.. list-table::
   :header-rows: 1
   :widths: 22 14 14 25 25

   * - cell
     - ``wpdepth``
     - ``tb-size``
     - median excursion
     - longest single
   * - ``pex_noend``
     - 64
     - default
     - 40 µs
     - 37.0 ms
   * - ``pex_wd4k``
     - 4096
     - default
     - 348 µs
     - 51.5 ms
   * - ``mkr_deep``
     - 65536
     - 4
     - 3.9 ms
     - 267.3 ms
   * - ``pex_deep``
     - 65536
     - 4
     - 3.9 ms
     - 492.0 ms

Read those as what they are: the granularity of the tracer's own work,
and the reason a capture at a large ``wpdepth`` takes the wall time it
does.  They are not a stall budget.  The guest's clock does not run
during any of them, so a 492 ms excursion is 492 ms of *your* time and
nought of the guest's.

**Where the cost goes at large depths.**  At ``wpdepth=65536``, 94.8 %
of excursions (22,965 of 24,230) ended early rather than exhausting
their budget, each after a median 3.9 ms.  Nearly all of that time buys
a walk that aborts, so the depth is being paid for rather than spent.
The figure is an aggregate because the reason an excursion ended early
is not recorded per valve — the instrument counts early exits, it does
not attribute them.

.. _delay-instrument:

Measuring the cost: ``CST_DELAY_DIAG``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``CST_DELAY_DIAG=1`` arms a diagnostic that attributes a vCPU **thread's
host** wall clock to the wrong-path walker.  It is off by default, it
takes no decision and ends no run, and it changes nothing the tracer
emits.  Everything it prints is host time; by the transparency argument
above, none of it is time the guest experienced.

Each vCPU's timeline between two consecutive excursion ends is
partitioned with no residue, every term measured at its own boundary::

    span = excursion wall + exec_lock wait wall + remaining gap wall

``occ`` is ``excursion / span``.  ``lock_ms`` is the exec_lock wait
billed in the reporting window.  The remaining gap is correct-path
instrumentation, guest execution, and any interval the host scheduler
had the thread off-CPU.  Both clocks are read at every excursion
boundary (``CLOCK_MONOTONIC`` and ``CLOCK_THREAD_CPUTIME_ID``), so
``sched = span_cpu / span_wall`` separates cost measured under host
contention (``sched`` well below 1) from cost that is really the
tracer's (``sched`` near 1).  A sampler thread reports on its own clock
— not from a callback — so an excursion that is *still open* is reported
with its current age (``inflight_ms``), and so is a lock acquisition
that has not completed (``lock_inflight_ms``).

**The** ``exec_lock`` **term, and why it needs its own name.**
``simulate_wrong_path_ext`` runs under ``exec_lock``, so on a
multi-vCPU guest the vCPU holding an excursion and the vCPUs queued
behind it are in entirely different states.  Before this term existed a
waiter's blocked interval fell into its own undifferentiated gap, where
it was indistinguishable from guest execution — and a vCPU that never
ran an excursion of its own was not printed at all, because only an
excursion boundary marked a slot as seen.  The report therefore showed
one busy vCPU and N-1 apparently quiet ones, which is the inverse of
what was happening.  A contended acquisition now marks the slot and is
billed on its own, whether or not that vCPU ever speculates.

``lock_ms`` is deliberately a duration and not a fraction.  A wait is
billed when it completes, so a wait longer than the reporting window
lands whole in the window it ended in; dividing by the window yields
quotients above 1 (8.78 was measured on the four-thread cell below) and
a ratio above 1 is not an occupancy.  Summed over a run — ``tot_lock_s``
— the billed figure is exact.  Uncontended acquisitions are not billed:
below a 1 µs floor the reading is the clock pair's own cost rather than
a wait, and counting those would turn the term into a tally of
correct-path blocks.

Knobs: ``CST_DELAY_DIAG_MS`` sets the sample window (default 250);
``CST_DELAY_DIAG_MIN_OCC`` suppresses windows below a threshold;
``CST_DELAY_DIAG_INJECT_US=<n>`` is a positive control that burns a known
``n`` microseconds inside every excursion, so the reported figure can be
checked against a delay of known size rather than merely observed to
move.  The injection distorts the run it is used on, by design.

Calibration of the excursion term, x86-64 user mode, single-threaded,
``wp=1 wpdepth=64``: injecting 100 µs moves the median reported
excursion from 5.83 µs to 106.20 µs — a measured 100.37 µs against 100
injected, 0.37 % error — and occupancy from 0.5269 to 0.9525, where the
gap term the baseline implies (5.23 µs per excursion) predicts 0.9530.
The duration reading and the partition are therefore both checked
against something external to the instrument, not merely observed to
respond.

Calibration of the ``exec_lock`` term reuses the same control on a
four-guest-thread x86-64 user-mode cell, where the injection lengthens
every excursion — and therefore every peer's wait behind it — by a known
amount:

.. list-table::
   :header-rows: 1
   :widths: 46 27 27

   * -
     - ``inject=0``
     - ``inject=200 µs``
   * - excursions, vCPU 1 / vCPU 2
     - 420,393 / 140,157
     - 420,358 / 140,114
   * - median excursion, vCPU 1
     - 10.39 µs
     - 206.94 µs
   * - exec_lock wait, summed over vCPUs
     - 13.7 s
     - 151.1 s
   * - longest single wait
     - 2.06 s
     - 30.18 s
   * - longest wait caught *still open*
     - 1.94 s
     - 30.10 s
   * - run wall clock
     - 13.8 s
     - 132.0 s

The workload is deterministic and both arms print the same result, and
the excursion counts are within 0.03 % of each other: the injection
changes what the tracer costs and not what the guest executes.  Against
that fixed workload the measured excursion grows by 196.6 µs for 200 µs
injected (1.7 % under), and the lock term grows 11x — so the lock
reading responds to a known perturbation of a known size and sign,
rather than merely being non-zero.

That cell also shows why the term was needed.  In the ``inject=0`` arm
vCPU 0 accrued **12.1 s of exec_lock wait inside a 13.8 s run** while
its own excursion occupancy was 0.0039.  Under the previous two-way
partition that entire quantity was invisible: it fell in the gap term,
and a vCPU whose occupancy is 0.0039 is exactly what an occupancy-only
report calls quiet.

What it does **not** measure, stated rather than left silent:

* The remaining gap is not decomposed.  The instrument brackets the
  ``exec_lock`` acquisition but not the correct-path step's body, so it
  cannot separate correct-path instrumentation from guest execution in
  what is left.  ``RtFactorGate``'s guest-realtime factor supplies that
  split by design, and the two are meant to be read together on one run
  (``CST_RT_TRACE=1 CST_DELAY_DIAG=1``).
* It costs what it measures with.  Armed, it adds ~1.07 µs per excursion
  (~10 % of wall on a cell running ~4 400 excursions/s), dominated by
  ``CLOCK_THREAD_CPUTIME_ID``, which has no vDSO fast path (~215 ns
  against ~31 ns for ``CLOCK_MONOTONIC``).  Both excursion-boundary reads
  are ordered so that the expensive one falls outside the interval it
  times, and the lock bracket reads only ``CLOCK_MONOTONIC`` — a thread
  blocked on a mutex accrues no thread CPU time, so the second clock
  would report nothing while doubling the cost of a bracket that sits on
  the correct-path step.  The instrument still perturbs the run by
  roughly a tenth: immaterial when hunting a hundredfold effect, and not
  to be quoted as a baseline.

An armed run that observes nothing at all says so once per window
(``no wrong-path excursion and no contended exec_lock acquisition has
been observed on any vCPU since arming``) rather than printing nothing,
so silence can never be misread as a measurement of health.

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
     - ``CST_FID_SLOT_COUNT`` = 512
     - ``LOAD_ADDR``/``LOAD_DATA`` slots 0..511.  There is no
       overflow vector; a single instruction issuing more than 512
       loads is not representable.  The widest x86 case is an
       ``XRSTOR`` reloading the extended state area, well inside the
       ceiling, and AVX-512 gather is only 16-wide; the one class that
       genuinely exceeds it is the AArch64 bulk-memory ``CPYM``
       (see :ref:`bulk memory <limits-bulk-memory>`).
   * - Slotted store addresses / data per instruction
     - ``CST_FID_SLOT_COUNT`` = 512
     - ``STORE_ADDR``/``STORE_DATA`` slots 0..511; likewise no
       overflow vector.  Sized by ``XSAVE``-family state saves — 88
       stores from one ``XSAVEOPT`` on a Haswell-class guest, about
       320 for a full AVX-512 area — and exceeded only by the AArch64
       bulk-memory ``SETM`` / ``CPYM`` (see :ref:`bulk memory <limits-bulk-memory>`).
   * - WP-side memops captured per instruction
     - ``CST_FID_SLOT_COUNT`` = 512
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
     - ``CST_FID_SLOT_COUNT`` same-PC iterations
     - A wrong-path instruction that never advances PC (e.g. an x86
       ``rep`` whose sandboxed write keeps PC anchored) is forced
       past once the same-PC iteration count *exceeds* the per-insn
       memop cap — past that point its memops are no longer
       representable, so further iterations record nothing.  A repeat
       that makes *no* progress at all (memop count not climbing) is
       bailed after two strikes and never waits for this bound.
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
single load/store value is encoded in up to 64 bytes.  ``rep movs``,
the AArch64 FEAT_MOPS bulk copy/set family, and any other instruction
whose memory fan-out a register bounds surface one body entry per
iteration (see the wire-format spec's *Bulk-memory self-loop BBs*
section), so each entry carries at most 1 load + 1 store — the
slotted ``LOAD_ADDR[0..511]`` / ``STORE_ADDR[0..511]`` (and matching
``DATA``) families cover every supported instruction; there is no
overflow vector, and the widest *bounded* single-instruction memop
fan-out on x86 — an ``XSAVE``-family state save, about 320 stores for
a full AVX-512 area — sits inside the 512 slots.

.. _limits-mem-value-width:

**A memop value wider than 128 bits is read back, not observed.**
QEMU hands a plugin the value of an access only up to ``MO_128``:
``CPUState`` latches just the low 128 bits, so
``qemu_plugin_mem_get_value()`` reports nothing above that (it returns
``QEMU_PLUGIN_MEM_VALUE_INVALID``; see ``plugins/api.c``).  For a
single access wider than that the tracer falls back to reading the
bytes out of guest memory itself, at callback time, capped at
``CST_MAX_WIDE_BYTES`` = 64.  Three consequences follow, and they
apply only to the value — the *address* and the *size* of such a
memop are always recorded:

* The value is the memory's CONTENT, not the transferred datum.  For
  a store it is read after the write has committed, which agrees with
  the stored value for an ordinary store but not for one whose bytes
  another agent changes in between.
* The read-back can fail (the page may no longer be readable).  The
  memop then carries its address and size and NO value: the data FID
  is simply absent, which a consumer must distinguish from a recorded
  value of zero by the FID's absence, not by its content.
* Past 512 bits the value is truncated to the low 64 bytes while the
  recorded size still reports the whole access.

In practice no in-tree target hands the plugin a memop wider than
``MO_128``.  SVE contiguous loads and RISC-V vector loads fall back to
instrumented per-element paths, so an ``ld1d`` at VL=512 or a
``vle32.v`` at LMUL=2 surfaces as many narrow memops, each with its
own value; AArch64 FEAT_MOPS bulk transfers are decomposed into
naturally aligned pieces of at most 16 bytes for exactly this reason
(``arm_plugin_bulk_mem_cb``, ``docs/qemu_modifications.rst``).  What
those families do run into is the slot ceiling below, not this one.

**Memops capped at 512 per insn.**  512 = ``CST_FID_SLOT_COUNT`` is
all an entry can address, in each direction, for one instruction.  On
the wrong path ``MemAccessRecorder::record`` stops recording past the
cap; on the correct path the accesses are recorded and the cap applies
when the entry is written, where the emitted ``N_LOADS`` / ``N_STORES``
is the *capped* count so that the entry stays self-describing — a
consumer is never promised more addresses than the entry carries.  The
per-run total left out this way is reported as ``Memops over slot
ceiling`` in the statistics summary.

.. _limits-bulk-memory:

**AArch64 bulk-memory instructions can exceed the slot ceiling.**
The FEAT_MOPS ``SETM`` and ``CPYM`` instructions are the one real class
that does.  QEMU implements the ``M`` member of each triple as "transfer
every whole page of the operation", so a single execution moves the
entire page-aligned body of a ``memset`` or ``memcpy`` — 3840 stores for
a 64 KiB ``memset``, against 512 addressable slots.  This is intrinsic
to the architecture, not to the wire: one instruction performs an
unbounded, register-sized transfer, so no finite slot count can address
it.  glibc routes ``memcpy`` / ``memmove`` / ``memset`` through these
instructions on any guest advertising ``HWCAP2_MOPS``, so it is reached
by ordinary code, not just by microbenchmarks.

What survives the cap: the ``P`` and ``E`` members of each triple are
architecturally bounded to less than a page each, so their accesses are
always represented in full, and ``M`` carries the first 512 accesses of
each direction — the leading, contiguous, 16-byte-strided run of the
transfer.  The per-template profile is not slot-bound and keeps the
untruncated ``memops_cp`` total and the full touched address extent, so
a consumer can see both how much traffic the instruction really did and
the address range it spanned.  The traffic that is lost is per-entry
slot detail in the interior of transfers larger than 8 KiB.

.. _limits-kernel-strand:

**Kernel-strand identity follows the guest kernel's own ``current``
contract.**  ``thread_id`` on a kernel block names the task that is
current while it runs.  For a task with a TLS base the producer learns
that from the same per-thread pointer register it uses for user code
(x86-64 ``FS.base``, AArch64 ``TPIDR_EL0``, MIPS CP0 ``UserLocal``):
those three are architecturally the kernel's to reload and nothing
else's, so Linux writes them from the incoming task at every context
switch and a non-zero read inside the kernel is exact.  A task with
*no* TLS base — every kernel thread, every per-CPU idle task, a
TLS-less user program — leaves that register 0, and for those the
producer falls back, at kernel privilege only, to where the kernel
itself keeps ``current``: AArch64 reports ``SP_EL0`` and MIPS ``$28``
iff the value is a kernel virtual address (the in-kernel homes of
``current`` and ``current_thread_info``; a user-shaped value means an
early entry window whose install has not run yet, and the sample
honestly declines so the strand inherits the entering thread — which
is the interrupted thread itself).  x86-64 keeps no per-task pointer
in a register at CPL0 — ``current`` is the per-CPU variable
``current_task`` behind the swapped-in kernel GS base at a link-time
offset — so its fallback is a read: given the per-image offset
(``curtask_off=``, derived from the kernel build's symbol table,
``System.map``, or the guest's ``/proc/kallsyms`` — the validator's
``derive_curtask`` module automates this), the producer dereferences
the kernel GS base at that offset, refusing the SWAPGS windows where
the user GS base is still live (entry before ``swapgs``, exit after
it, the paranoid NMI/#DB/#MC paths' brackets) exactly as the
AArch64/MIPS entry windows are refused.  Without ``curtask_off`` the
x86-64 fallback does not exist and every TLS-less task shares the id
minted for 0 — the offset is decided at kernel link time, differs per
build, and reading a guessed one would mint *wrong* identities rather
than merged ones, so absence degrades to honest indistinctness.
Kernel threads therefore split into per-task strands (the per-CPU
idle tasks included) wherever the fallback can answer, and the
kernel-entry alias joins a TLS-less thread's two raw identities (0 in
user, its task pointer in kernel) at the exception edge so kernel
work done on a thread's behalf keeps that thread's id.
**RISC-V reaches the kernel-privilege guarantee by a
different route.**  No single RISC-V register names the task at every
privilege: the S-mode trap entry swaps ``tp`` with ``sscratch``, so the
task pointer moves between the two registers four times per trap and
either register read alone is wrong in some window.  The *pair* is
exact, because the task pointer is always whichever of the two holds a
kernel virtual address — a ``task_struct`` lives in the kernel's direct
map; a user TLS base and the ``0`` sentinel do not.  The producer
selects on that, so a RISC-V sample at U or S privilege reports the
kernel's current-task pointer: one identity value space across
privilege, and kernel strands are distinguished exactly as they are on
the other three targets.  Note the consequence for the *value* — a
RISC-V thread's identity is its ``task_struct`` pointer, not its user
TLS base.  Two contexts stay outside the contract: **M-mode firmware**,
which runs on its own ``tp`` with the S-mode ``sscratch`` parked, and
**H-extension virtualization**, where ``vsscratch`` and not ``sscratch``
is the swapped register.  A guest with no S-mode OS below it, or one
that never arms ``sscratch``, leaves neither register looking like a
kernel address and degrades to the raw ``tp``.

Wherever a kernel block does carry the thread that merely *entered* the
kernel on that vCPU rather than the one running — the two RISC-V
contexts above, or work left behind on a vCPU the traced thread has
migrated off — the block is credited to the wrong thread, and two such
strands can braid inside one ``(thread_id, asid)`` context.  At *user*
privilege no fallback exists — there is nothing but the TLS register to
read — so where it is never written (a MIPS model without
``Config3.ULRI``, a guest that sets no TLS) every user thread reports 0
and user-privilege entries collapse to one id: honest indistinctness,
not fabricated identity.  Their kernel excursions still resolve
per-task through the kernel-privilege fallback, and the entry alias
keeps each excursion on the id of the thread that entered; only
distinct *user* bodies remain unseparated.  On x86-64 without
``curtask_off`` the kernel side collapses too, as described above.

On the targets where the sample *is* trusted at kernel privilege, the
handoff lands where the guest kernel declares the incoming task — the
``switch_to()`` write, a few instructions ahead of the actual stack
switch — so a short run of instructions inside the scheduler is credited
to the incoming task while the outgoing one is still architecturally
executing.  The window is bounded by that fixed instruction distance and
is entirely inside kernel scheduler code.

**Kernel coverage follows the content gate.**  A kernel block is
traced exactly when the address space it executes in maps a latched
window's marker bytes (the same one-bit rule user blocks follow):
kernel code reached from a gated context — syscalls, fault handlers,
borrowed-mm kernel threads, post-switch tails still on the gated page
tables — is the traced flow's, and kernel work of a context that maps
no marker bytes is not captured.  A guest that switches to a private
kernel page-table base on entry — KPTI on — runs its kernel excursions
in a context that maps no marker bytes, so kernel coverage stands down
to nothing there; KPTI off is the configuration this tracer is
characterised on.

**A speculatively fetched syscall is never performed.**  The WP
simulator walks *past* a syscall, software interrupt or trap at its
architectural fall-through — an out-of-order frontend fetches around
one and squashes it at retire — but the call itself is suppressed, so
its result registers hold the deterministic placeholder rather than a
real return value.  Dependents of a wrong-path syscall therefore
execute on synthetic data, which is the same contract every other
wrong-path fault carries and is marked the same way
(``CST_BB_FLAG_SYNTHETIC_FAULT`` with ``CST_FID_BB_FAULT_INSN`` naming
the syscall).  What is *not* modelled is the
kernel side: the trace never contains the handler a wrong-path syscall
would have entered, because the correct resolution is a privilege
escalation and no real core commits one on a mispredicted path.

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

**A marker window ends at its END marker, so a process that dies
without executing one leaves its window open.**  A marker-bookended
region ends where the workload says it ends; that is the terminator,
and there is no second one.  Under ``policy=latch`` a process that
exits — killed, crashed, or simply never reaching its END marker —
therefore leaves its window open, and the capture is finalised when
the machine goes down: the machine-shutdown close writes the file out
on a vCPU thread with the guest still assembled, marks the segment
``SHUTDOWN``, and counts it as ``closed by machine shutdown``.  Ending
a system run with ``/workload ; poweroff -f`` is what that looks like
in practice.  ``latch_timeout=<ms>`` closes a window idle for longer
than a given wall-clock interval, for runs where waiting for the
shutdown is inconvenient; it is opt-in and off by default, because
idleness alone cannot distinguish a dead process from a merely
long-blocked live one.

**The trace filter is content-at-vaddr, so scope follows the bytes.**
At every committed address-space change the tracer reads the marker
sequence's bytes at each latched window vaddr through the live context
and traces the context exactly when they match.  No root, ASID or
process id is ever stored or compared as an identity, so there is no
recycling exposure, no re-bind rule and no proof-of-life probe: a
successor process either maps the latched bytes (and is, by the
contract, traced — concurrent instances, same-binary successors and
fork children are all deliberately in scope) or it does not (and is
not).  The residual obligations are stated positively: the marker page
must stay resident (``mlock(2)`` before START; a *gated* context whose
marker page stops being readable gates off, counted by ``gated context
lost marker page residency`` — a foreign context that never mapped the
bytes lands in ``gate refresh evaluated NOT traced`` alone), and
a process that wants out compiles the marker out.  The opt-in
window-closing backstops for a process that dies without its END
marker — ``latch_timeout=<ms>`` and ``latch_idle_insns=<N>`` — reduce
to ONE global last-gated-execution stamp pair: the segment closes when
every gated context has been idle past the threshold (per-window aging
while another gated window still executes is deliberately retired —
v4 default, maintainer-vetoable).


**Wrong-path excursions are time-transparent, but not free.**  An
excursion consumes zero guest time — the guest virtual clock is frozen
for its duration, the instruction counter is checkpointed under
``-icount``, and every clock, host timer and interrupt line is
resynchronised to the frozen time on exit (QEMU's
``TCGCPUOps::spec_clock_resync``; see :doc:`qemu_modifications`).  What
that buys is that the guest observes the same tick count, and takes the
same interrupts, whether wrong-path simulation is on or off.  What it
does not buy is wall-clock parity: a traced system-mode run advances
guest time only while the guest is actually executing, so it takes
several times longer in real time than an untraced boot, and anything
outside the guest that measures real time — a host-side watchdog, an
NTP peer, an interactive session — sees that stretch.  Time *inside*
the guest remains self-consistent.

Decode-metadata bounds
----------------------

The dependency model is only as good as the per-instruction operand
metadata the decoder supplies, and that metadata comes from Capstone by
way of the correction boundary in ``disas/capstone.c``.  Because every
self-consistency check the tracer owns reads the *same* metadata, a
decoder defect corrupts the trace and the checks agree with the
corruption.  The independent instrument for that class is the
``isaxcheck`` cross-check (:doc:`validator`, gating check
``features.isa_crosscheck``), which compares the boundary's answer
against the LLVM MC layer over an exhaustive sweep of the opcode-bearing
encoding space on all four ISAs.  What follows are the gaps it leaves
standing, each recorded rather than fixed.

**SME is not modelled.**  Capstone reports the AArch64 ZA matrix
accumulator and its tile/slice operands as a dedicated ``SME`` operand
type — a tile, a slice-select general-purpose register and an immediate
index in one operand — and the plugin's operand ABI has exactly one
register slot per operand.  Every SME instruction therefore loses its
accumulator dependency, and the slice-select register with it.  Closing
this needs an operand-ABI extension, not a boundary correction.  The
neighbouring SVE forms are unaffected.

**SVE predicate registers are modelled; the predicate's runtime VALUE is
not.**  Predicate registers occupy ``REG_PRED0``..``REG_PRED31`` in the
generic register space, and the whole predicated dataflow edge is
recorded: a predicate producer (``ptrue``, ``whilelt``, the
predicate-writing compares, ``brka``/``brkb``) records its destination,
a predicated operation records its governing predicate as a source, and
the predicate-to-predicate logical ops record both.  What the tracer does
not do is *evaluate* a predicate at decode time.  For memory that costs
nothing — the per-lane memory callbacks already reflect the active lanes,
so a ``ptrue p0.s, vl4`` gated load fans out to exactly four memops and a
``vl2`` gated load to two.  For a predicated register operation the lane
mask is the static full-width one: an inactive lane is not excluded from
the destination's lane set.  A consumer that needs per-lane liveness on a
masked arithmetic op has the predicate register dependency but must
derive activity itself.

**SME's second predicate field is dropped.**  An SME predicate operand
carries a governing predicate *and* a vector-select register; only the
first is represented, for the same one-slot reason as above.

**An instruction with more than sixteen operands loses the rest.**
``qemu_plugin_insn_info`` carries ``QEMU_PLUGIN_INSN_DETAIL_MAX_OPS``
= 16 operands, and the boundary truncates past that.  No instruction
in any supported ISA reaches it: the widest family is the SME2
four-vector-group form, where ``bfmls za.h[w8, 7, vgx4],
{ z0.h - z3.h }, { z4.h - z7.h }`` carries nine — the ZA tile plus
eight Z registers — and Capstone's own operand array holds sixteen,
so the cap matches the decoder's own ceiling rather than sitting
below it.  The cost is confined to the template dictionary: the
per-instruction decode struct widens by about 48 bytes per added
slot, and the body stream, which references templates by id rather
than carrying operands, is unaffected.

**Cumulative FP exception status is not modelled.**  AArch64 ``FPSR``
and the RISC-V ``fflags`` accumulation are written by every FP
instruction that can raise an exception; the tracer records neither.
The register model carries dataflow registers, and threading a
read-modify-write of one status word through the whole FP stream would
put every FP instruction on a serial chain no implementation renames —
a false dependency on that scale misleads a consumer further than the
missing edge does.  The *control* half is modelled in full: ``FPCR``
and ``frm`` are read wherever the rounding mode is an input, and an
explicit ``msr fpsr`` or ``fscsr`` is a real write of ``REG_FCSR``.

**RISC-V ``vstart`` is modelled only where it is moved explicitly.**
Architecturally every vector instruction reads ``vstart`` and clears
it.  The tracer records ``REG_VSTART`` only for the ``csrr`` /
``csrrw`` accesses that name it: outside a mid-instruction trap resume
``vstart`` is zero and stays zero, so threading it through every vector
op would serialise the vector stream on a register whose value never
changes.

**The tail-undisturbed RVV destination read is not statically
decidable.**  Under ``vtype.vta == 0``, ``vtype.vma == 0`` or
``vstart > 0`` a vector destination keeps its previous contents in the
inactive elements, which makes ``vd`` a source of nearly every vector
instruction.  Those bits live in a CSR an earlier ``vsetvl`` wrote, so
a per-opcode template cannot express the dependency without carrying
``vtype`` in its key, and the tracer does not model it.  The one
sub-case that *is* decidable from the instruction word is modelled:
when the destination is a **mask** register — the integer and FP
compares, ``vmadc``/``vmsbc``, the mask-logical ops,
``vmsbf``/``vmsif``/``vmsof`` and ``vlm.v`` — the mask tail is
undisturbed regardless of ``vta``, so ``vd`` is recorded as a source.

**MIPS coprocessor banks collapse.**  Every coprocessor register folds
onto ``REG_SYS``, so COP0 register 3 and COP2 register 3 are one slot;
every FP control register folds onto ``REG_FCSR``, so are ``FCR0`` and
``FCR31``.  The HI and LO halves of a MIPS accumulator likewise share
one ``REG_ACC`` slot.  These are deliberate: the dependency model
tracks the hazard, not the architectural bank.  The registers pulled
back out of ``REG_SYS`` are the ones where the collapse invented edges
rather than merging them — the ``rdhwr $29`` thread pointer
(``REG_TLS``), ``DSPControl`` (``REG_DSPCTRL``) and MSA's control word
(``REG_VCSR``).

**Wrong-path decode of arbitrary bytes is best-effort.**  Capstone
accepts encodings whose architecturally-fixed fields hold reserved
values.  ``0x88c08022`` has ``Rs != 0b11111`` and ``Rt2 != 0b11111`` and
is therefore not a valid ``LDAR``; Capstone decodes it as
``ldar w2, [x1]`` where LLVM rejects it, and 28 such signatures exist on
AArch64 and 4 on MIPS.  On the correct path the bytes never occur.  On
the wrong path, where the tracer decodes whatever the mispredicted target
happens to contain, it means a template can describe a plausible
instruction where the hardware — and QEMU — would raise UNDEFINED.  The
tracer does not reject these: rejecting them would replace a
plausible-but-wrong instruction with no instruction at all, which is a
worse model of a machine that fetches and decodes down a wrong path
before the fault resolves.  Wrong-path *instruction identity* is
best-effort by design; wrong-path *control flow* and *addresses* are not.

Reproducibility caveats
-----------------------

See :ref:`reproducibility` in the quickstart for the invocation
that pins the byte-stability breakers (ASLR, kernel-supplied
randomness, process identity, host scheduling, inherited
environment).  With those pinned, a single-vCPU user-mode trace
is bit-deterministic, wrong path included; what follows is the
boundary of that statement.

**A trace is exactly as reproducible as the guest's input.**
The tracer records what the guest did, so anything the guest can
read that differs between two runs comes back as a difference in
the trace, and the wrong path magnifies it: a mispredicted path
dereferences values the program never would, so one differing
byte becomes an address, a load at that address, and the branch
that load decides.  A measured example is worth more than the
rule.  Two runs of a static-glibc x86_64 binary at a fixed build
with ASLR off and ``-seed 1`` differed in 33,186 body lines and
in the wrong path's fault and atomic counts.  The whole
difference came from two guest-visible inputs that were not
pinned: ``set_tid_address`` returned the host tid (glibc stores
it in the TCB during start-up), and ``getrandom`` returned host
entropy into the ``.bss`` word glibc uses as its pointer guard.
Pinning both with ``-pid`` and ``-seed`` took 12 of 12 repeat
traces to a single hash; without either, 12 of 12 were distinct.

**What is genuinely outside the pin.**  A workload that reads a
clock, a workload given different file descriptors (an
``fstat`` of a redirected stdout puts that file's inode into
guest memory), and a multi-threaded workload whose vCPUs
interleave differently.  These are properties of the run, not of
the tracer, and the tracer records them faithfully; hold them
still at the harness level when byte-stability is required.

**Diagnostic consequence.**  When a wrong-path A/B comes back
with a large diff, do not read it as many independent
divergences.  Find the *first* differing record and identify
which side it is on: in every case measured so far it was a
single value on the correct path, and everything after it was
that one value propagating.

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
