Troubleshooting and FAQ
=======================

Common failure modes and their fixes.  If your situation isn't here,
the first stop is the exit-time stderr summary (every plugin run
prints one) and ``cst_audit trace.cst`` (per-section byte counts);
together they answer most "why does my trace look like X" questions.

Build and install
-----------------

**``configure`` reports Capstone as disabled, or not found**

Nothing the tracer builds uses it.  The repository carries no
Capstone source, no wrap and no vendored copy; the option
``configure`` prints is upstream QEMU's own, governing QEMU's
``-d in_asm`` disassembler and nothing the plugin or its tools
touch.  The fork's own build passes ``--disable-capstone`` so the
emulators it produces link none either.

**``ninja contrib/plugins/libchampsim_tracer.so`` fails with
"unknown type qemu_plugin_insn_info"**

The plugin assumes the plugin-API additions described in
:doc:`qemu_modifications`.  Building against an unmodified upstream
QEMU base will fail with this error or similar.  Either rebase your
plugin checkout onto the patched QEMU fork, or backport the
``include/qemu/qemu-plugin.h`` and ``disas/capstone.c`` patches.

**Plugin loads but reports ``unknown option: foo``**

The plugin refuses to install on any unknown ``key=value`` pair so
typos surface immediately rather than producing a misconfigured
trace.  Compare your invocation against :doc:`quickstart`'s flag
catalog; common typos: ``warmup_insns=`` (correct: ``warmup=``),
``simulation_insns=`` (correct: ``simulation=``).

Trace generation
----------------

**Trace is much larger than expected**

Run ``cst_audit trace.cst`` and look at the body breakdown.  The
usual culprits, in order:

1. ``CP field-delta section`` >> 50% of the body: ``memdata=1``
   data captures dominate.  Drop to ``memdata=0`` if values aren't
   needed.
2. ``WP field-delta section`` is large: ``wp_memdata=1`` (default
   inherited from ``memdata``) captures the speculative cache-
   pollution stream's *values*.  Set ``wp_memdata=0`` to keep
   addresses but drop values — usually the biggest single
   trace-size knob.
3. ``IFRAME records`` shows nontrivial bytes: an ``iframe_rate``
   was set in this run.  Drop to ``iframe_rate=0`` once you've
   verified decoder reproducibility — IFRAMEs are pure validation
   redundancy.
4. In a **system-mode** trace: a ``physical pages`` line appears when
   ``physaddr=1`` adds a physical-page base to every memop, and
   ``DEVIO START`` / ``DEVIO STOP`` records appear when the guest does
   disk I/O (``devio`` is on by default).  Set ``physaddr=0`` /
   ``devio=0`` if you don't need them; both are user-mode no-ops, so
   they never inflate a user-mode trace.

**``GEN_OP_UNKNOWN`` appears in the exit summary**

Capstone returned an instruction-id the tracer couldn't classify.
Each per-ISA classification table is sized to that ISA's
Capstone ``*_INS_ENDING`` count (``X86_INS_ENDING``,
``AARCH64_INS_ENDING``, ``RISCV_INS_ENDING``, ``MIPS_INS_ENDING``)
and carries a designated initializer for every Capstone-defined
mnemonic.  The two causes are:

* Capstone returned an invalid insn-id, because the bytes it was
  handed are not a valid instruction encoding — most often
  uninitialized memory the program executed by mistake, or a
  privileged instruction Capstone does not fully model.
* The Capstone the tracer was built against is older than the
  Capstone that emitted the insn-id — a newer Capstone added a
  mnemonic the table does not yet cover.

Either way, the per-PC details are in the
``<basename>.unknown_warnings.log`` sidecar — ``pc=``, ``mnemonic=``,
and the disassembled string of the offending instruction.

**``WP simulations skipped = N`` is large**

The counter tallies sealed BBs whose resolved wrong-path target is
zero — no plausible alternate edge exists, so no excursion is
kicked.  The common sources: unconditional direct jumps and calls
(one architecturally-fixed target, nothing to mispredict toward),
monomorphic indirect branches under ``wpprune``, cold branches the
``wpprune`` level suppresses, and BBs without a classified branch
terminator.  Skipped branches still appear in CP; they just have an
empty ``wp_entries`` list.  See ``resolve_wrong_target`` and
``wp_branch_pruned`` in ``champsim_tracer.cc`` for the resolution
logic.  A high count on a ``wpprune=0`` run of ordinary code
usually just reflects a call-heavy instruction mix.

**``trace_window=marker: policy must be 'latch' or 'trace-all'``**

The marker window's ``policy=`` key accepts only ``latch`` (the
default — each process that runs the START marker is traced until its
own END marker) and ``trace-all`` (the first START captures every
context).  A marked process that exits *without* running its END
marker leaves its window open until the segment's icount budget
closes it; set ``latch_timeout=<ms>`` to instead close a window that
has been idle — never scheduled — for that many wall-clock
milliseconds.

**``no valid simpoints in: <file>``**

The simpoints file format is whitespace-separated lines, one
simpoint per line:

.. code-block:: text

   <interval_id> <cluster_id>

Where ``interval_id`` is the simpoint position in units of the
``interval`` instructions passed in ``trace_window=simpoint:``.
An optional sibling ``.weights`` file (``<weight> <cluster_id>``
per line) is loaded if present.
If your file is empty, has comments-only, or all entries are
malformed, the plugin reports this error and refuses to install.

**``champsim_tracer: cannot open <member> output: ...``** (or
**``... cannot open <member> compression pipe: ...``**)

The directory for the ``outfile=`` path doesn't exist or isn't
writable, so the plugin could not open a trace-archive member (or,
with ``compress=`` set, could not start its compression pipe).  The
plugin doesn't ``mkdir -p`` for you; create the target directory
before invoking QEMU.

**A ``<outfile>.cst.body_tmp[.<codec>]`` file with no ``<outfile>.cst``**

The run ended without a close.  The body member streams to this
temporary file for the whole life of a segment, but the header member
(templates, register schema — everything a decoder needs) is buffered
in memory and only written at ``finish``, when the two are assembled
into the outer ``.cst`` archive and the temporaries unlinked.  A run
that dies before that point — ``SIGKILL``, a crash, ``abort()`` (which
skips ``atexit`` and therefore the plugin's exit hook), or the
guest-realtime gate's deliberate ``_exit`` after declaring the guest
wedged — leaves exactly this signature: an orphaned body temporary and
no archive.  The orphan is **not** a salvageable trace; without the
header member its bytes cannot be decoded, and no tool will try.  It
is left in place, deliberately, as postmortem evidence of where the
body stream stopped.

Distinguish it from the neighbouring signature: **both** temporaries
(``.body_tmp`` and ``.header_tmp``) next to a missing ``.cst``, with a
``tar assembly failed`` message on stderr, mean the close itself ran
and only the final archive step failed (disk full, permissions).

Trace decode
------------

Both tools treat any malformed or truncated ``.cst`` input the same
way: a diagnostic message on stderr and a clean exit code 1, never a
crash.  A length-prefixed section that over- or under-consumes
relative to its own declared length, a reference to a template id the
templates section never defines, or a stream that ends mid-record all
surface through this path.  If a trace instead aborts (a signal, not
a clean rc=1), that is a tool bug — file an issue with the offending
file rather than assuming the trace itself is merely corrupt.

**``cst_decode`` errors with ``IFRAME with no preceding ENTRY``**

The trace's body stream starts with an IFRAME record before any
ENTRY.  This is a writer bug or a corrupt trace; if it reproduces,
file an issue with the offending ``.cst`` file.

**``cst_decode`` errors with ``Footer entry-count mismatch``**

The number of ENTRY records the body-walker observed doesn't match
the count in the body footer.  Indicates either a truncated trace
file (check ``cst_audit``'s file-size vs. trailer offsets) or a
writer bug.

**Trace contains addresses that don't match my binary's symbols**

Most common cause: ASLR.  Disable with ``setarch -R`` on the QEMU
command line, or compile the workload as ``-fno-pie -no-pie`` for a
fixed-load-address ELF.  Cross-reference the ``start_pc`` /
``symbol_name`` fields in the templates section with the binary's
``readelf -s`` output to confirm.

**Two back-to-back runs produce different traces**

See :ref:`reproducibility`.  Common causes: ASLR, multi-threaded
scheduling, clock-driven guest behavior, and kernel-supplied
randomness.  Apply the quickstart's recommended invocation
(``taskset -c 0`` to pin host scheduling, ``setarch -R`` to disable
ASLR, ``-seed N`` to fix ``AT_RANDOM``, ``env -i`` to strip the
inherited environment) and fix any ``gettimeofday()``-driven
dispatch in the workload; the body streams should then be
byte-stable across runs (the ``DATETIME`` and ``COMMAND`` strings
in the header still differ — those just record metadata).

Plugin runtime
--------------

**Plugin aborts with a SIGSEGV in glibc near process exit**

A TLS destructor ordering issue vs the plugin's per-thread
accumulator on some glibc versions.  Workaround: the
plugin avoids ``shrink_to_fit`` in atexit precisely to dodge this
crash; if you've added new atexit-time cleanup, look at
``cleanup_current_thread`` in the source.  See the "Thread-locals
at exit" caveat in :doc:`architecture`.

**Per-segment summary shows ``Branch transitions observed = 0`` for
a segment that clearly has branches**

Indicates a segment that opened but never saw a branch instruction
finish (e.g. a segment 1 instruction wide that opens between
fragments of a basic block).  Increase the segment window size.

**``starting segment 'trace' [icount 0 .. unbounded]`` is the only
stderr line**

The QEMU command exited before any TB executed.  The workload
probably crashed before reaching its first instruction, or the
guest binary failed to start (missing dynamic linker, missing
shared library, wrong target ISA).  Run without ``-plugin`` to
isolate.

System-mode guest timing
------------------------

**A system-mode run never reaches its budget: the segment closes
``UNDER``, the guest console goes quiet, and ``trace_arch_insns`` is
tens or hundreds of times ``user_covered``**

The guest has stopped taking interrupts and is spinning in the
kernel.  The tracer is working correctly — it is faithfully recording
the spin — so the trace itself is well-formed and every structural
check passes; the only signature is the accounting.  Healthy
system-mode runs sit between roughly 1 and 8 traced architectural
instructions per covered user instruction; a wedged guest runs into
the hundreds.

That ratio is only meaningful once the window has covered a few
thousand user instructions.  Below that, fixed per-segment overhead
(guest boot, marker injection, the first scheduler passes before the
workload gets the CPU) dominates the denominator and the ratio reads
high *by construction* — a normal ``END`` close (the workload simply
exited early, having done little work) at a few hundred covered
instructions is the common shape here, not a corner case.  The
validator's ratio leg only judges segments past that floor
(``CLOCK_INFLATION_MIN_COVERED`` in ``_system.py``); the ``UNDER``-close
leg has no such floor and always fires, since closing under budget is
a failure at any window size.

The cause is a guest clock that did not survive a wrong-path
excursion: a host timer left parked, an interrupt line left
disagreeing with its pending register, or an externally-asserted
interrupt erased by the excursion's register rollback.  Guest-time
transparency is QEMU's ``TCGCPUOps::spec_clock_resync`` contract (see
:doc:`qemu_modifications`), and every system-mode target registers
it.  If you have added a target, or a new clock source to an existing
one, that hook is where it has to be reconciled.

To confirm the diagnosis rather than infer it, re-run with ``wp=0``:
without wrong-path excursions there is nothing to freeze and the
symptom disappears.  Note that ``-icount`` also hides it — its
deterministic scheduling serialises the iothread — so a run that is
healthy only under ``-icount`` is evidence *for* this cause, not
against it.

The validator gates on all three symptoms directly, on all four
ISAs, in ``system.clock_progress_<isa>``.

The guest stops making progress under system-mode tracing
---------------------------------------------------------

A system-mode capture can enter a state where the guest keeps executing
but never finishes its workload: it services its periodic timer tick,
schedules, and comes straight back to the next tick.  Two out of every
three instructions a healthy capture window retires are already tick and
scheduler service on an idle host, so the margin to that state is thin,
and host contention — most sharply an SMT sibling under load — can spend
it.  A capture that enters it and is left alone writes a trace that
passes every content check while carrying tens of times the healthy
architectural instruction count.

The tracer reports the relevant quantities at exit, unconditionally::

  champsim_tracer: guest_realtime factor=0.087 worst_sample=0.038 samples=9
    in_segment_host_s=2.49 guest_s=0.217 insn_per_guest_s=2.679M
    segment_insns=581343 ticktax=0.6747 worst_user_stall=44582
    stall_detector=live

``segment_insns`` is the instructions the guest retired while the capture
was open, printed exactly.  A consumer must use it rather than recover it
from the rate beside it; see the stall-condition section below for what
that reconstruction costs.

``ticktax`` is the fraction of retired guest instructions spent inside
asynchronous interrupts.  It describes what the guest retired, not
whether the guest is healthy, and it does **not** select the stall
condition: across 3,838 marker cells the ratio never exceeded 0.794, and
in the stalled cells it reads *lower* (p50 0.689) than in healthy ones
(p50 0.703).  On this fixture two thirds of everything the guest retires
is interrupt work in every cell, stalled or not, because the guest is
otherwise idle.  Read it to understand a trace's composition; do not
read a value below 1.0 as a clean bill of health.

``worst_user_stall`` is the field that selects the condition: the largest
number of instructions the guest retired without the traced process
executing a single user-space instruction — the healthy value on the
canonical cell is tens of thousands, and a stalled capture reads millions
to hundreds of millions.  ``stall_detector=INERT`` means the
user-instruction clock never moved inside the segment, so nothing was
watching.

Environment knobs (all detection only; none changes what is traced):

``CST_RT_GATE``
   Arm the progress detector.  Any value arms it; a non-zero value
   additionally arms a guest-realtime-factor floor.  On a trip the
   tracer prints the counts and the reason and exits with status 88.

``CST_RT_STALL``
   Retired-instruction budget for the stall detector (default
   8 000 000, about 100x the healthy worst case).  Setting it also
   ARMS the stall detector, so it is usable on its own; a knob whose
   only effect is on a tripwire it does not arm reads as protection
   and is not.

``CST_RT_GATE_STREAK`` / ``CST_RT_GATE_WINDOW_MS``
   Consecutive sub-floor sample windows required to trip the factor
   floor, and the host span of one sample window (default 8 x 250 ms).

``CST_RT_TRACE``
   Print every sample (``[rtsample] t=... f=... insn=... ticktax=...
   stall=...``) for offline distributions.

``golden_net.py`` arms the detector for the canonical system cells and
additionally re-checks the ratio of architectural instructions to
workload instructions against the value recorded at capture, which is
what catches a wedge that finished anyway.

The **validator deliberately does not arm it**, and this page used to
claim it did.  The reason is written where the decision is made
(``_system.py``, ``run_with_clock_watchdog``): the budget is calibrated
on the canonical devio cell, and the churn cell runs the marked workload
alongside a stream of short-lived processes, so the traced process is
legitimately off-CPU while the guest retires millions of instructions in
other address spaces.  Armed globally the detector called that a wedge —
it did, on ``system.churn_x86``.  Until the budget is recorded per
workload, the validator passes through only what the operator set.

Recognising the state, and the one test that discriminates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Score a capture on whether **its segment closed**, never on how long the
cell took.  A capture in this state prints ``starting segment 'marker'``
and never the ``end marker — closing`` / ``finished segment … END`` pair,
so the window is still open when the run is stopped and the cell's
``stats.log`` is empty because the close that writes it never ran.  The
window is open for want of an END, not for having ignored one: the END
marker is a user-space instruction, and in this state the guest stops
retiring user-space instructions before reaching it.  On the canonical
cell that is measurable to the instruction — 40 of 40 closing cells end
at a machine-wide user-instruction count of 7,058,329 to 7,058,585,
because the END terminates the run where it is crossed, while the
non-closing cell's user count stops at 7,045,897 and never moves again.
The close machinery is therefore not the place to look; the reason the
traced task never runs again is.  Elapsed time does not discriminate.  Under host contention a
healthy cell can spend minutes inside the window and still close — cells
that stalled for over two minutes and then finished normally sit in the
same waves as the ones described here.  A capture held in this state to
the end of the run closes never; one that comes out of it closes, and
ships a trace carrying the episode (see
:ref:`troubleshooting-escaped-stall`), so the close is where to start
reading and not where to stop.

On the canonical x86_64 marker cell the state has a constant shape:

* the machine's user-instruction stream stops — not the traced process's
  alone, every process's — at a point reproducible to within a few
  hundred instructions across runs, about twelve and a half thousand user
  instructions short of the END marker.  A guest merely starved of host
  CPU stops wherever it happens to be; this one stops in the same place
  every time;
* the guest is neither idle nor stopped.  Kernel instructions keep
  retiring, and fast: 113.7 million of them over the 8.6 guest-seconds
  (160 host-seconds) that followed the last user instruction in the
  measured cell, which is 13.2 M per guest-second and 0.71 M per
  host-second.  Guest time keeps advancing and interrupts keep being
  delivered — 5,239 async windows over those 8.6 guest-seconds, and 14.8%
  of everything retired in them is interrupt context.  Sampled program
  counters land in the CFS accounting band and nowhere else:
  ``update_curr``, ``update_load_avg``, ``update_cfs_rq_load_avg``,
  ``__update_load_avg_cfs_rq``, ``___update_load_sum``,
  ``entity_eligible``, ``cpuacct_charge``, ``rb_add_augmented_cached``,
  ``min_deadline_cb_propagate``.  The scheduler never picks a user task
  again;
* every wrong-path corruption instrument reads zero across the episode —
  device-register digests, the armed-deadline digests for all three
  clocks, the interrupt gain/loss counters.  Nothing is corrupted.

.. _troubleshooting-escaped-stall:

The episode that ends, and the trace it leaves behind
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A capture that never closes is caught by whatever bounds the run.  The
one that matters is the capture that spends a long stretch in this shape
and then comes out of it: the guest reaches its END marker, the window
closes, the ``.cst`` is assembled, and every content check passes.  What
that trace carries is not what the workload did.

The measurement is direct, because the shape is fixed: 1350 canonical
x86_64 marker cells across five build arms all cover 854 to 857 user
instructions, so the kernel work a capture carries is comparable cell to
cell.  Over the 1325 that closed, the architectural instructions carried
per instruction of user coverage read as follows.

==================================== ==================== ================
                                     arch insns / covered stall_fraction
==================================== ==================== ================
median of the 1325                                  168.5            0.165
90th percentile                                     178.4            0.215
15 cells                                    637 to 8,197   0.579 to 0.949
==================================== ==================== ================

The most extreme of those closed normally, exited zero, and shipped a
trace holding 7,025,221 architectural instructions where the median cell
of the identical workload holds 144,000 — 45 times the kernel work, for
the same 857 user instructions.  The distribution between the two is
continuous, and it continues without a break into the cells that were
killed before they could close.  Where an outer bound happens to cut is
therefore not where the condition begins, and *"the segment closed"* is a
necessary reading, not a sufficient one.

``stall_fraction`` above is what the validator gates on, and it is
computed from the two architectural counts the tracer already prints:

.. code-block:: text

    stall_fraction = worst_user_stall / segment_insns

— the largest number of instructions the guest retired between two
advances of the traced process's user clock, over the instructions it
retired while the capture was open.  A reading of 0.949 says that
ninety-five per cent of everything the machine retired inside the capture
happened in one stretch during which the traced process did not execute a
single instruction.  Nothing in it is a time, a rate or a cost, so it
reads the same on an idle host and a saturated one.

Both terms must come from the report verbatim.  ``segment_insns`` is
printed for exactly that reason: recovering it as ``insn_per_guest_s x
guest_s`` divides by a guest clock printed to three decimals, and that
clock is frozen across every excursion, so a marker window can close
inside a few milliseconds of it.  At ``guest_s=0.003`` the three decimals
are a 17 per cent quantisation — wider than the whole distance from the
healthy band to the gate — and the reconstruction has been measured
3.2 times larger than every instruction the guest retired in the run.

The report also carries an EXACT form of the stretch, maintained per
executed TB rather than on a sampling grid: the ``stretch_exact`` line
gives the worst no-traced-user stretch with zero bias in either
direction, its composition (asynchronous-interrupt work, kernel work in
the gated context, kernel and user work in foreign contexts), the
machine-wide user-privilege retirement count, and a strided ring of the
stretch's TB start PCs (``stretch_ring``) that names kernel work against
the guest's symbol map.  The validator scores the exact fields whenever
they are present: no resolution bound applies, and the verdict is
two-term — the stretch must dominate its segment AND exceed an absolute
abnormality floor derived from the measured corpus, so a micro-window
whose single timer tick dominates a tiny denominator is adjudicated with
its composition printed rather than convicted on a ratio.  The
machine-wide user count also resolves the off-CPU ambiguity directly: a
workload whose marked process is legitimately off-CPU (the validator's
churn cell) shows its foreign user retirement in the composition instead
of reading as a stall.  The self-consistency arithmetic still applies to
every report: the stalled instructions and the traced user instructions
are disjoint subsets of the segment, so
``worst + traced_icount <= segment_insns``, and a report that violates it
has contradicted itself and is not scoreable.  Reports written before
``stretch_exact`` existed carry only the SAMPLED reading, whose grid has
no reliable direction and certifies nothing on a short segment; the
``stall_fraction + 2/samples <= gate`` bound applies to those alone.

Reproducing it, and why a zero needs its own power
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The class is open by standing rule even with its known mechanisms
closed, and any frequency it has moves with host contention, so an
attempt to observe it has to bring its own contention rather than wait
for the machine to supply some, and has to be sized against the
frequency of **the tree being tested** rather than one measured on
another tree.

The shape that produces it is the canonical marker cell — window
``marker:simulation=3000000+policy=latch``, ``wpdepth=64``, one vCPU
pinned to a single core, a 180 s harness cap — with that core's SMT
sibling held busy for the life of the cell and the rest of the host under
memory-bandwidth load.  Cells are cheap, a healthy one closing in
seconds, so the practical unit is a wave of a few hundred scored on the
close.  Interleave the arms of any comparison cell by cell instead of
running one arm and then the other: the frequency tracks host load over
tens of minutes, and the same tree measured before and during a quiet
period differs by more than any two trees do — the tree that produced 8
non-closes in 120 cells under load produced none in 105 when the machine
went quiet.

The mechanism behind the measured episodes was found by intervention —
an input/output thread's consumption of a VIRTUAL timer deadline racing
the wrong-path interposition — and is closed by construction at
``34e55de9fc``: exactly one consumer evaluates VIRTUAL deadlines, at
slice breakouts, and the racing consumer does not exist in the shipped
binary.  Post-fix, the canonical cell measures 0 stalls in 24 under the
full contention recipe (``e57d01c938``), and the exact-stretch
re-adjudication at ``ee5f9a0191`` reads 0 gate failures over 52 cells
and all four ISA batteries, every over-gate ratio decomposing as
asynchronous-interrupt work inside a micro-window with zero foreign
activity.  Rates measured on earlier trees are deliberately not quoted
beside those numbers: identically shaped waves on one tree have been
measured differing several-fold with the cause unfound, so cross-wave
rate ladders mislead — compare arms only when they are interleaved cell
by cell inside one wave.  The class itself stays open by standing rule:
a fix closes a mechanism, never the class, and a green battery is
exposure, not proof of absence — which is why the detector remains armed
and its zero still needs the power analysis above.

Where to look next
------------------

* :doc:`quickstart` — flag catalog with full descriptions.
* :doc:`limitations` — out-of-scope categories and known issues.
* :doc:`architecture` — internal flow loops, performance characteristics.
* :doc:`format` — wire-format specification.
