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

Where to look next
------------------

* :doc:`quickstart` — flag catalog with full descriptions.
* :doc:`limitations` — out-of-scope categories and known issues.
* :doc:`architecture` — internal flow loops, performance characteristics.
* :doc:`format` — wire-format specification.
