Troubleshooting and FAQ
=======================

Common failure modes and their fixes.  If your situation isn't here,
the first stop is the exit-time stderr summary (every plugin run
prints one) and ``cst_audit trace.cst`` (per-section byte counts);
together they answer most "why does my trace look like X" questions.

Build and install
-----------------

**``configure`` complains about Capstone**

The plugin requires Capstone built with detail mode and links
against the revision pinned in the QEMU meson wrap at
``subprojects/capstone.wrap`` (currently ``6.0.0-Alpha7``).  The
wrap auto-downloads that revision; make sure ``--enable-plugins``
was passed and that the wrap was allowed to fetch (some CI
environments disable wrap downloads — pass ``--with-capstone`` or
pre-populate ``subprojects/capstone/``).

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

Capstone workaround maintenance
--------------------------------

**Retiring a Capstone workaround**

``disas/capstone.c`` carries roughly a dozen boundary workarounds for
access-flag and operand-modelling defects in Capstone 6.0.0-Alpha7, the
revision ``subprojects/capstone.wrap`` pins.  Each lives behind a
narrowly-scoped predicate function (``cap_x86_is_test``,
``cap_aarch64_infer_mem_access``, ``cap_fill_mips_operands``'s inline
MSA/unaligned check, ...), and each function's comment states three
things: the Capstone version the defect was observed on, the exact
encodings affected — and, just as load-bearing, the sibling encodings
Capstone already reports correctly, which is what makes the defect
credible as a narrow Capstone bug rather than a misunderstanding of the
architecture — and a ``cstool`` one-liner or
``capstone_workaround_probe`` case name to re-check it.

None of these workarounds are meant to be permanent.  Each is scoped to
one opcode, one operand size, or one instruction family specifically so
that a fixed Capstone makes the corresponding predicate a silent no-op
rather than newly wrong; the intent is to retire them individually as
upstream Capstone fixes land, not to carry them indefinitely.  The
retest procedure below is the single documented way to find out which
ones a given Capstone bump has already fixed.

*Procedure:*

1. Bump ``subprojects/capstone.wrap``'s ``revision`` to the new
   Capstone tag or commit and reconfigure.
2. Rebuild: ``ninja -C build contrib-plugins``.  This rebuilds
   ``disas/capstone.c`` too (it links into ``libcommon.a``, shared by
   every QEMU target binary) along with the plugin and offline tools.
3. Run ``build/contrib/plugins/capstone_workaround_probe``.  It
   re-derives the same minimal repro bytes cited in each
   ``disas/capstone.c`` comment, decodes them with whatever Capstone
   the binary was linked against, and reports each workaround as
   ``STILL NEEDED``, ``RETIRE CANDIDATE``, or ``INCONCLUSIVE`` (the
   last meaning the repro bytes themselves failed to decode at all —
   the case needs updating before it says anything about the bug).
   The tool always links ``subprojects/capstone`` — the same
   dependency ``cst_decode`` uses — never a system Capstone; see below
   for why that distinction matters.
4. Run the decoder cross-check, which sweeps the whole encoding space
   rather than one representative per family::

      python -m champsim_tracer_validator full --build-dir build \
          --only features.isa_crosscheck

   This compares the boundary's answer for 1.58 G encodings against the
   LLVM MC layer — 1.25 G x86_64, 164 M aarch64, 151 M mipsel, 16.8 M
   riscv64 — a couple of minutes for all four ISAs at ``--jobs=16``.
   It is the complement of the probe: the probe says
   whether a workaround has become *unnecessary*, the cross-check says
   whether the boundary's overall answer is still *right*.  A bump that
   fixes one defect and regresses another shows up here even when every
   probe case reports ``RETIRE CANDIDATE``.  New disagreements are
   listed by signature; triage each into
   ``tools/isaxcheck_allow.txt`` with a justification, or fix it.
5. A ``RETIRE CANDIDATE`` means Capstone now reports *that one
   representative encoding* correctly, not necessarily the whole
   family the comment documents.  Hand-sweep the rest of the family
   with the ``cstool`` invocations quoted in the comment (again, a
   ``cstool`` built from ``subprojects/capstone`` — see
   ``subprojects/capstone/cstool/README.md``, or just ``cd
   subprojects/capstone/cstool && make``) before trusting it.
6. Once a family is confirmed fixed end to end, delete its predicate
   function, its call site(s) in the relevant ``cap_fill_*_operands``,
   and its case(s) in ``capstone_workaround_probe.cc``, all in the same
   change.  Re-run the golden nets
   (``contrib/plugins/champsim_tracer/tests/golden_net.py check`` and
   ``--system``) and the full validator (``python -m
   champsim_tracer_validator full``) before committing the removal —
   a workaround retirement is expected to change decode output for the
   handful of encodings it used to correct, so treat a byte-identical
   golden net as a sign the affected encodings never appeared in the
   golden corpus (check by hand with ``cst_decode --format=disasm``),
   not as confirmation the removal was safe.

*Why not just trust a system* ``cstool``:  a system-installed
``cstool`` is routinely a different Capstone major version than the one
QEMU actually links — confirmed during authoring of this procedure:
this project's development host has Capstone 5.0.1 on ``$PATH``, three
major versions behind the 6.0.0-Alpha7 the wrap pins.  None of the
defects documented in ``disas/capstone.c`` reproduce against 5.0.1; a
system ``cstool`` reports the *already-fixed* behavior for every one of
them, which looks identical to "this workaround is retirable" but
proves nothing about the Capstone QEMU actually builds against.  Always
build ``cstool`` from ``subprojects/capstone`` (matching
``capstone.wrap``'s pinned revision) before running a ``cstool``
command a workaround comment suggests, or skip the ambiguity entirely
and use ``capstone_workaround_probe``, which links the correct copy
unconditionally and cannot make this mistake.

The three-way decoder tripwire
------------------------------

``isaxcheck`` compares two decoders: the tracer's boundary
(``cap_disas_raw_detail()`` in ``disas/capstone.c`` — Capstone plus
every correction the boundary applies) and the LLVM MC layer.  Those
two are not independent.  Capstone's AArch64, Mips and RISCV
instruction tables are auto-synced from LLVM TableGen, so a defect the
two share is structurally invisible to any comparison between them.

``tools/isax3way.py`` adds a third opinion — GNU binutils/opcodes,
through the cross ``objdump``\ s — whose opcode tables are a separate,
hand-maintained codebase.  It runs the boundary and LLVM through
``isaxcheck --batch`` (one TSV row per encoding, carrying both
decoders' views and echoing the input bytes back in a ``hex`` column),
disassembles the same bytes with ``objdump``, joins the three on
``hex``, and buckets every disagreement::

   contrib/plugins/champsim_tracer/tools/isax3way.py \
       --isaxcheck build/contrib/plugins/isaxcheck --out 3way/

About five seconds for aarch64, riscv64 and mipsel on the checked-in
representatives, fifteen with executed populations added.  Each
report is a ``.3way`` file naming the buckets, their encoding counts,
their dynamic weight if an executed population was supplied, and three
sample encodings apiece:

``V-accept=…``
   validity vote — which of the three accepted the encoding at all.
``L-cs=…,llvm=…,gnu=…``
   instruction-length vote.
``M-cs=llvm!=gnu``, ``M-gnu=llvm!=cs``, ``M-cs=gnu!=llvm``, ``M-all-differ``
   mnemonic vote.  ``M-cs=llvm!=gnu`` is the shared-blind-spot
   signal; ``M-gnu=llvm!=cs`` says binutils broke the tie against the
   boundary.
``X-…``
   the registers named in the *explicit* operand text, same voting
   scheme.

An ``X-`` bucket on a branch instruction deserves a look at its sample
before it is believed.  binutils renders a branch target as a bare
section-relative hex address with no ``0x``, and such an address can
spell an ABI register name — ``jal fa6`` is a target, not a write of
``fa6`` — so whether the bucket appears at all depends on where the
encoding happened to land in the batch.  The other three vote classes
have no such ambiguity.

**Why this is periodic and not per-commit**

binutils yields disassembly *text*.  No access metadata, no def/use
sets.  So it can rule on encoding validity, instruction length,
mnemonic identity and explicitly-named registers, and on nothing
else — a strict subset of what ``isaxcheck`` already checks on every
commit, over a far smaller population.

What it uniquely answers is a *version* question.  When the boundary
decodes an encoding LLVM rejects, there are two very different
explanations: the LLVM subtarget in ``isaxcheck``'s ``kIsaTable`` is
narrower than the Capstone mode the tracer runs in, or Capstone is
over-accepting an encoding the architecture reserves.  binutils
separates them.  ``V-accept=cs`` — binutils rejecting alongside LLVM —
is unambiguously the second; ``V-accept=csgnu`` puts the encoding
beyond Capstone's word alone and points at the first, with the
qualification below.  The per-commit gate now
measures the *size* of that gap directly and reports it as
``subtarget_gap=`` on its summary line, so the standing need is not to
re-derive the interpretation every commit but to confirm it still
holds after a decoder moves underneath it.

Run it on a Capstone bump (``subprojects/capstone.wrap``), an LLVM
bump, or a binutils bump, and diff the new ``.3way`` reports against
the previous run's.  The bucket names are stable across versions of
the tool on purpose: a bucket-by-bucket diff is the whole deliverable.

**Reading a nonzero** ``V-accept=csgnu``

Two independent decoders accept an encoding LLVM refuses, so the
encoding is not a Capstone invention.  The default reading is that the
LLVM subtarget is missing the feature that decodes it, and the fix is
to widen the subtarget — add the LLVM feature to that ISA's
``features`` string in ``isaxcheck``'s ``kIsaTable`` — **not** to add a
line to ``tools/isaxcheck_allow.txt``.  An allowlist line hides the
encoding from the register, memory and branch comparisons entirely,
because a rejection short-circuits the whole compare; the gate would
then be blind to exactly the extension the tripwire just proved
exists.

An allowlist line is correct only when there is no LLVM feature left
to enable.  AArch64 is that case and is worth knowing as the worked
example: its subtarget is already ``+all``, there is nothing wider to
select, and its residual ``V-accept=csgnu`` is Capstone and binutils
*both* being lenient about fields the architecture reserves —
``08400022`` decodes as ``ldxrb w2, [x1]`` in both even though ``Rs``
and ``Rt2`` are not the required all-ones, and LLVM enforces them.
Shared leniency between two decoders is not evidence of a missing
feature.  So the third opinion narrows the question rather than
answering it outright: ``V-accept=cs``, with binutils rejecting
alongside LLVM, is unambiguously Capstone alone; ``V-accept=csgnu`` is
either a subtarget gap or a shared over-acceptance, and which one it
is follows from whether the ISA has a feature left to turn on.

**Populations, and why the sweep is not exhaustive**

Two populations feed the tool.  The representatives, checked in under
``tools/isax3way_pop/<isa>_rep.hex``, are the structured
opcode-space sweep decimated to at most 24 encodings per distinct
*three-way answer* — the answer being each decoder's verdict and
mnemonic, which is the whole of what binutils can testify to.  Every
bucket the exhaustive sweep produces therefore survives into the
representative population by construction; what is capped is bucket
magnitude.  Magnitude that matters comes from the second population:
the encodings a real workload actually retired, passed with ``--hex
aarch64=run.hex`` and weighted by execution count with ``--weights
aarch64=run.weights.tsv``, which is what turns a bucket from
"reachable" into "reached ten million times".  Regenerate the
representatives after a decoder bump with ``--gen-rep`` (minutes, not
seconds — it walks the full sweep).

Exhaustive is not merely slow on AArch64, it is unavailable.
binutils 2.42's AArch64 disassembler aborts on an assertion::

   aarch64-linux-gnu-objdump: ../../opcodes/aarch64-dis.c:251:
   get_sreg_qualifier_from_value: Assertion `value <= 0x4 &&
   aarch64_get_qualifier_standard_value (qualifier) == value' failed.

The abort is reachable only *in sequence*: the same encoding
disassembled on its own decodes cleanly as ``.inst 0x… ; undefined``.
binutils carries decoder state across instructions (the MOVPRFX
sequence constraint), so it is the adjacency an exhaustive sweep
creates that trips it, and no single-encoding test finds it.  On this
project's development host — binutils 2.42, Ubuntu — the 4 194 304-
encoding AArch64 sweep dies with ``SIGABRT`` at encoding 1 531 836
(``0x5d7ef022``), and the aborts come in dense storms: six
4096-encoding regions of the opcode space in which very nearly every
encoding aborts.  ``isax3way.py`` survives them by resuming past the
offending
slot with an exponentially growing quarantine distance, answering the
quarantined slots ``(gnu-internal-error)`` and counting them in the
report's ``#gnu-internal-errors`` line.  That is a reportable binutils
defect, not a decode opinion — and it is why the third opinion runs on
representatives rather than on the full space.

x86_64 is deliberately out of scope.  Capstone's x86 tables are
hand-maintained and independent of LLVM's, so the shared-blind-spot
argument that motivates a third opinion does not apply, and x86
already has Intel PIN cross-validation.

Where to look next
------------------

* :doc:`quickstart` — flag catalog with full descriptions.
* :doc:`limitations` — out-of-scope categories and known issues.
* :doc:`architecture` — internal flow loops, performance characteristics.
* :doc:`format` — wire-format specification.
