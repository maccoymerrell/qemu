Troubleshooting and FAQ
=======================

Common failure modes and their fixes.  If your situation isn't here,
the first stop is the exit-time stderr summary (every plugin run
prints one) and ``cst_audit trace.cst`` (per-section byte counts);
together they answer most "why does my trace look like X" questions.

Build and install
-----------------

**``configure`` complains about Capstone**

The plugin requires Capstone with detail-mode + group classification
support.  The QEMU meson wrap at ``subprojects/capstone.wrap``
auto-downloads a known-good version; make sure
``--enable-plugins`` was passed and that the wrap was allowed to
fetch (some CI environments disable wrap downloads — pass
``--with-capstone`` or pre-populate ``subprojects/capstone/``).

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

**``GEN_OP_UNKNOWN`` appears in the exit summary**

Capstone returned an instruction-id the tracer couldn't classify.
Each per-ISA classification table is sized to ``CAPSTONE_INS_ENDING``
and has a designated initializer for every Capstone-defined
mnemonic, so this almost never reflects a missing table row in
practice.  The two real causes:

* Capstone returned an invalid insn-id (often because the bytes it
  was handed are not a valid instruction encoding — most often
  uninitialized memory the program executed by mistake or a
  privileged instruction Capstone doesn't fully model).
* The Capstone version the tracer was built against is older than
  the Capstone version emitting the insn-id (newer Capstone added
  a mnemonic the table doesn't yet cover).

Either way, the per-PC details are in the
``<basename>.unknown_warnings.log`` sidecar — ``pc=``, ``mnemonic=``,
and the disassembled string of the offending instruction.

**``WP simulations skipped = N`` is large**

The WP simulator skips branches whose
``branch_type`` it can't classify into a known WP-target shape
(usually because the per-ISA classifier left the branch as
``BRANCH_NONE`` or routed it through an opcode the WP target
resolver doesn't handle).  Skipped branches still appear in CP;
they just have an empty ``wp_entries`` list.  See
``resolve_wrong_target`` in ``champsim_tracer.cc`` for the
classification logic.

**``no valid simpoints in: <file>``**

The simpoints file format is whitespace-separated lines, one
simpoint per line:

.. code-block:: text

   <interval_id> <cluster_id>

Where ``interval_id`` is the simpoint position in units of
``spinterval`` instructions.  An optional sibling ``.weights``
file (``<weight> <cluster_id>`` per line) is loaded if present.
If your file is empty, has comments-only, or all entries are
malformed, the plugin reports this error and refuses to install.

**``cannot open binary output: <path>``**

The directory for the ``outfile=`` path doesn't exist or isn't
writable.  The plugin doesn't ``mkdir -p`` for you; create the
target directory before invoking QEMU.

Trace decode
------------

**``cst_decode`` errors with ``IFRAME with no preceding ENTRY``**

The trace's body stream starts with an IFRAME record before any
ENTRY.  This is a writer bug or a corrupt trace; if it reproduces,
file an issue with the offending ``.cst`` file.

**``cst_decode`` errors with ``footer entry-count mismatch``**

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
scheduling, clock-driven guest behavior.  Pin ``-smp 1``, disable
ASLR, fix any ``gettimeofday()``-driven dispatch in the workload,
and the body streams should be byte-stable across runs (the
``DATETIME`` and ``COMMAND`` strings in the header still differ —
those just record metadata).

Plugin runtime
--------------

**Plugin aborts with a SIGSEGV in glibc near process exit**

Pre-existing issue with TLS destructor ordering vs the plugin's
per-thread accumulator on some glibc versions.  Workaround: the
plugin avoids ``shrink_to_fit`` in atexit precisely to dodge this
crash; if you've added new atexit-time cleanup, look at
``cleanup_current_thread`` in the source.  See the "Thread-locals
at exit" caveat in :doc:`architecture`.

**Per-segment summary shows ``branches_observed = 0`` for a segment
that clearly has branches**

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
