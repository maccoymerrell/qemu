Quickstart
==========

This page covers building the plugin, running it against a guest, and
reading the trace it produces.

Building
--------

Prerequisites
~~~~~~~~~~~~~

The tracer is a C++17 QEMU TCG plugin.  It was developed and tested on linux,
with the following toolchain and library version(s); other environments may work but are untested.:

* **OS:** Ubuntu 22.04 / 24.04.  Other
  Linuxes likely work; macOS is untested; Windows builds via the
  meson plumbing but is not exercised in CI.
* **Compiler:** gcc 11+  C++17 is required.
* **glib:** 2.66 or newer (Ubuntu 22.04 default is fine).
* **Capstone:** auto-downloaded by meson via
  ``subprojects/capstone.wrap``.  The plugin uses Capstone's
  detail mode and requires the revision pinned in that wrap
  file (currently ``6.0.0-Alpha7``); the build always links
  against that pinned copy.
* **QEMU base:** the repository is a fork of QEMU.  The plugin
  expects the base modifications described in
  :doc:`qemu_modifications`; building against an unmodified
  upstream QEMU will not work because the plugin uses
  ``qemu_plugin_insn_detail``, ``qemu_plugin_cap_decode``, and
  ``qemu_plugin_insn_branch_target_pc``, which this fork provides and
  upstream QEMU does not.

Build invocation
~~~~~~~~~~~~~~~~

A reduced-target configure that builds only the user-mode targets
the tracer supports:

.. code-block:: console

   $ ./configure --enable-plugins \
                 --target-list=x86_64-linux-user,aarch64-linux-user,riscv64-linux-user,mipsel-linux-user
   $ ninja -C build contrib-plugins

``contrib-plugins`` is the alias target that builds the plugin
shared object and the offline tools (``cst_decode``, ``cst_audit``)
in one shot.  Output lands under ``build/contrib/plugins/``.

A full configure (system mode included) also works; the user-mode
restriction above just trims build time.  Capstone is downloaded
and built automatically the first time you ``configure`` for a
target that needs it.

If your distribution ships a stale Capstone (some do), the meson
wrap takes precedence — the plugin always builds against the wrap
copy under ``subprojects/capstone/``.

Running the tracer
------------------

Attach the plugin to a user-mode QEMU invocation with ``-plugin``:

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wpdepth=64 \
                 ./your_program

The plugin name before the comma is followed by ``key=value`` pairs
parsed by ``parse_plugin_options`` in
``champsim_tracer_plugin_config.cc``.  Unknown keys cause the plugin
to refuse to install (the entire QEMU run aborts before the guest
starts).  Numeric values are parsed with ``atoi`` (decimal) for the
small-int options and with ``g_ascii_strtoull`` (decimal,
arbitrary-precision) for the icount-shaped options.

The options are grouped by responsibility below.  Defaults come from
the ``PluginConfig`` struct in
``champsim_tracer_plugin_config.h``; the "applied default" line for
each option says what the global ends up holding when you don't pass
the flag.

Output destination
~~~~~~~~~~~~~~~~~~

.. index::
   single: outfile
   single: compress

``outfile=<basename>``
   Basename for the trace files.  Default ``champsim_tracer_out``.
   The plugin writes:

   * ``<basename>.cst`` — the binary trace, a POSIX ustar archive
     carrying a ``body.cst[.<codec>]`` member and a
     ``header.cst[.<codec>]`` member.  A trailing ``.cst`` in the
     user-supplied basename is stripped before the suffix is appended,
     so ``outfile=run`` and ``outfile=run.cst`` both produce
     ``run.cst``.  In simpoint mode the per-segment files are named
     ``<basename>-<positionB>.cst``, where ``<positionB>`` is the
     simpoint position expressed in billions of instructions with the
     decimal point rendered as ``_`` (so the only ``.`` is the ``.cst``
     extension).  For example, ``outfile=mcf`` yields ``mcf-42B.cst``
     for a simpoint at 42 billion instructions and ``mcf-73_4B.cst``
     for one at 73.4 billion.  The trailing ``.cst`` on the user
     basename is also stripped for these.
   * ``<basename>.unknown_warnings.log`` — sidecar with one line per
     Capstone-emitted instruction the per-ISA classifier didn't
     recognize.  Empty when the classification table covers your
     workload.

``compress=<shell command>``
   Per-member compressor command.  Default unset (each member is
   written uncompressed).  The tracer spawns the command via
   ``popen()`` once for the body member and once for the header
   member; the resulting payload is bundled into the outer ``.cst``
   archive under e.g. ``body.cst.zst`` / ``header.cst.zst``.  Typical
   values: ``compress="zstd -T0 -3 -q -c"``, ``compress="xz -T0 -2
   -c"``, ``compress="gzip -c"``.  The member suffix is inferred from
   the first word of the command.

Segmentation
~~~~~~~~~~~~

These options carve up the run into one or more *segments*.  A
segment is one bounded window of guest execution captured into
its own stand-alone ``.cst`` file — independently decodable,
with its own header / templates dictionary / body stream and its
own per-segment statistics summary on stderr.  The three modes
below differ in how many segments a single QEMU run emits and
how the segment boundaries are picked:

* ``icount``, ``symbol``, and ``marker`` modes each produce exactly
  **one** segment per run and write a single ``<basename>.cst``.
* ``simpoint`` mode produces **one segment per simpoint** listed
  in the input file and writes **one ``.cst`` file per segment**,
  named ``<basename>-<positionB>.cst`` (see the ``outfile=``
  description above for the position-encoding rule).

Segments never share a body stream: when simpoint mode emits N
segments, you get N independent traces a decoder can process in
any order.  Each segment opens at its window's start icount,
writes its own header at finish, and the next segment begins
fresh.

.. index::
   single: trace_window
   single: trace_window; icount mode
   single: trace_window; simpoint mode
   single: trace_window; symbol mode
   single: trace_window; marker mode
   single: segmentation
   single: simpoint mode
   single: symbol mode
   single: marker mode
   single: warmup_insns
   single: simulation_insns

The single config option that controls segmentation is
``trace_window=MODE:KEY=VALUE+KEY=VALUE+...``: it forces the user to
pick exactly one mode and rejects keys that don't apply to it (so
``warmup=`` under ``icount`` is an error rather than a silent
no-op).  The inner KEY=VALUE list uses **``+``** as the separator —
``+`` is not a shell metacharacter, so the whole plugin argument
needs no quoting.  ``;`` is also accepted for back-compat but
requires shell-quoting the ``-plugin`` value (unquoted ``;`` is a
command separator).  Commas can never appear inside the value
because QEMU's plugin-argument parser splits on commas before the
plugin sees its argv.

``trace_window=icount:start=<lo>+stop=<hi>``
   Single contiguous window in instruction-count space.  The
   only legal keys are ``start`` and ``stop``.

``trace_window=simpoint:file=<path>+interval=<insns>+warmup=<insns>+simulation=<insns>``
   One segment per simpoint listed in ``file``.  ``interval``
   defaults to ``100000000`` and must match the granularity used to
   *generate* the simpoint file.  ``warmup`` (default ``0``) traces
   that many insns *before* each simpoint position so cache /
   branch-predictor warm-up data is captured.  ``simulation``
   (default ``0`` traces one ``interval`` length) traces that many
   insns *at and after* the simpoint position.  ``warmup`` is only
   meaningful here (you can't warm up before an arbitrary icount or
   symbol occurrence — see ``symbol`` mode below) and is rejected
   under the other two modes.

   **Simpoints file format.**  ``file`` is consumed verbatim in the
   `SimPoint <https://cseweb.ucsd.edu/~calder/simpoint/>`_ tool's own
   output format, so the file ``SimPoint`` writes with
   ``-saveSimpoints`` can be passed straight through:

   * Each non-empty line is ``<interval_id> [<cluster_id>]``,
     whitespace-separated, one line per selected simpoint.
     ``interval_id`` is the 0-based interval index; the chosen
     interval covers instructions
     ``[interval_id * interval, interval_id * interval + interval)``.
     ``cluster_id`` (the phase id ``SimPoint`` assigns) is optional;
     when omitted, the line's ordinal is used.
   * Lines beginning with ``#`` and blank lines are ignored.  Line
     order does not matter — segments are emitted in ascending
     instruction-count order.
   * An optional sibling weights file (``SimPoint``'s
     ``-saveSimpointWeights`` output) is loaded automatically if
     present: it is the path with a trailing ``.simpoints`` replaced
     by ``.weights`` (or, for any other name, ``<file>.weights``).
     Each line is ``<weight> <cluster_id>``; the weight is recorded
     on the matching simpoint for downstream aggregation and does not
     affect what is traced.

   Example ``mcf.simpoints`` / ``mcf.weights`` pair::

      # mcf.simpoints          # mcf.weights
      42 0                     0.5123 0
      178 1                    0.3001 1
      933 2                    0.1876 2

``trace_window=symbol:name=<sym>+occurrence=<N>+simulation=<insns>``
   Trace begins on the *N*-th time the named symbol appears as a
   basic-block entry, then runs for ``simulation`` architectural
   instructions before the process is exited (or for the rest of
   the run when ``simulation=0``).  ``occurrence`` defaults to
   ``1`` (the first time the symbol is hit).  No ``warmup`` —
   we can't predict what executes before an arbitrary symbol's
   *N*-th occurrence, so this mode opens the segment at the
   matching TB's first instruction.  Symbol matching uses
   ``qemu_plugin_insn_symbol`` on the TB's first instruction; the
   symbol name must match exactly (no demangling, no fnmatch).

``trace_window=marker:simulation=<insns>+policy=latch|trace-all``
   Guest-driven window for **system-mode** tracing
   (``qemu-system-<isa>``).  The workload carries a magic marker
   instruction sequence at its entry point; when it executes, the
   segment opens there, pins to the executing process's address
   space, and traces ``simulation`` of that process's *user-space*
   instructions (its synchronous kernel calls are traced but not
   counted against the budget).  A matching end-marker in the
   workload closes the window early when the program finishes under
   budget.  ``simulation`` and ``policy`` are the only legal keys;
   ``simulation`` must be positive when given, and with no key list
   the window spans 1 million user instructions.  See the
   *System-mode tracing* section of :doc:`architecture` for the
   marker contract, the address-space pin, and what a system-mode
   trace contains.

   ``policy`` governs what happens once more than one process is
   running the marker sequence concurrently:

   * ``latch`` (default) — each process that runs the *start* marker
     joins the traced set on its own; the segment closes once every
     joined process has run its *end* marker (or the icount budget is
     met), whichever comes first.  See the ``latch_timeout=`` bullet
     below for the backstop that closes a joined process's window if
     it dies without reaching its end marker.
   * ``trace-all`` — the *first* start marker widens capture to every
     context/ASID in the system (no foreign-process filtering) until
     that first process runs its end marker or the icount budget is
     met.  Only the capture gate widens: the icount clock and
     end-of-window detection still ride that first marker process's
     user instructions, so the owned set stays the single clock pin.

   To trace an **unmodified binary** (no compiled-in marker), run it
   inside the guest under :program:`cst_attach`, which injects the
   marker at the target's entry point via ``ptrace``::

      cst_attach ./workload arg1 arg2

   :program:`cst_attach` runs *inside the guest*, on the guest's own
   binary, so it is a guest-architecture program: the copy built by
   ``ninja -C build contrib-plugins`` is a host binary and only serves a
   guest of the host's architecture.  For any other guest, cross-build
   it against that guest's toolchain and stage it into the rootfs::

      aarch64-linux-gnu-gcc -std=gnu11 -O2 -static \
          contrib/plugins/champsim_tracer/tools/cst_attach.c \
          -o sysroot/bin/cst_trace

   Static linking matters: a busybox rootfs has no dynamic loader for a
   foreign toolchain's libc.  Injector backends exist for the four ISAs
   the tracer targets — x86/x86-64, AArch64, RV64, and little-endian
   32-bit MIPS.  A big-endian MIPS guest is *not* covered, because the
   marker encoder emits a little-endian instruction stream; on any other
   host/arch pair :program:`cst_attach` refuses to run rather than
   mis-inject.  The validator cross-builds and stages the injector for
   you under ``--system --attach`` (:doc:`validator`).

   Because the tracer is single-address-space and kernel-code
   per-thread attribution is only clean while the process stays on one
   vCPU, ``cst_attach`` confines the target to a single guest CPU by
   default (``--pin-cpu N`` selects the CPU, ``--no-pin`` disables the
   confinement).  A compiled-in marker gets the same guarantee from
   ``taskset``/``isolcpus``.  If a pinned process migrates across vCPUs
   anyway, the plugin emits one ``pin_multivcpu_observed`` warning per
   segment — pin it to a core for clean per-thread attribution.

   .. important::

      System-mode tracing assumes a specific guest and device
      configuration: kernel page-table isolation off (``nopti``), the
      traced process pinned to one vCPU, and — for disk-I/O records — a
      ``virtio-blk`` disk with ``ioeventfd=off`` and no dedicated
      iothread.  These knobs and why each one matters are collected in
      :ref:`canonical-system-config`.

``latch_timeout=<ms>``
   Dead-latch detector for the marker *latch* policy
   (``trace_window=marker:policy=latch``, the default marker policy),
   where each process that runs the start marker joins an owned set and
   is traced concurrently until it runs its **end** marker.  A process
   that instead *dies* — killed, or exits without ever reaching its end
   marker — would otherwise leave its window open forever: "all windows
   closed" never fires and only the icount budget closes the segment.

   When ``latch_timeout`` is non-zero the tracer stamps each owned
   process's last schedule-in (wall time) and, off the hot path, closes
   any window that has gone idle — never scheduled — for longer than the
   given number of milliseconds, exactly as that window's end marker
   would.  A live dominant process ages out a dead peer through its own
   user-clock progress; when the *last* window closes this way the whole
   segment shuts down (the backstop for a set of processes all killed at
   once).

   Default ``0`` disables it.  The signal is wall-clock idleness, which
   cannot tell a dead process from a merely long-idle live one — a
   process blocked on I/O, sleeping, or (for a system pin) starved by
   heavy foreign scheduling churn all look idle.  So the detector is
   opt-in: enable it for latch traces where processes may die without
   their end marker, and choose a timeout comfortably larger than the
   longest idle any *live* process in the workload legitimately exhibits
   (seconds, typically), trading detection latency against the risk of
   closing a slow-but-alive window early.

Examples::

   trace_window=icount:start=0+stop=20000000
   trace_window=simpoint:file=mcf.sp+interval=100000000+warmup=2000000+simulation=20000000
   trace_window=symbol:name=main+occurrence=3+simulation=20000000
   trace_window=marker:simulation=20000000
   trace_window=marker:policy=latch+simulation=20000000 latch_timeout=2000
   trace_window=marker:policy=trace-all+simulation=20000000

Without ``trace_window=`` the segment opens at process start and runs
until the guest exits — equivalent to ``trace_window=icount:start=0``
with no upper bound.

Wrong-path simulation
~~~~~~~~~~~~~~~~~~~~~

.. index::
   single: wrong-path simulation
   single: wp
   single: wpdepth
   single: wp_memdata
   single: wp_regdata

**What "wrong-path" means here.**  At every CP branch the tracer
runs an extra side-trip: it picks the *other* target the branch
predictor might have chosen and runs basic blocks down that path
until ``wpdepth`` instructions have been speculatively fetched.
The simulator drives QEMU's TCG to actually execute those
instructions, mutating registers and attempting stores, so the
recorded WP chain reflects the architectural state a real
mispredicting machine would have produced.  Stores route through
a per-vCPU speculative store buffer rather than touching guest
memory; loads see that buffer overlaid on the real address space.
At the end of each WP chain the saved CPU state is restored — the
correct path resumes from exactly where the branch was first
observed, mirroring how a real machine squashes the wrong-path
work when the misprediction is resolved.

This is the right shape for cache-pollution and prefetcher-
training research: the recorded WP entries carry the same memops
and register snapshots a real machine's speculative window would
generate.  It is *not* a cycle-accurate model — branch-mispredict
penalty timing lives in the consumer simulator, not the trace —
and it does not nest mispredicts: branches *inside* the
speculative window follow their statically-resolved direction
rather than spawning further wrong-path chains.

``wp=0`` / ``wp=1``
   ``1`` (default) enables wrong-path simulation: every CP branch
   gets a speculative chain of WP basic blocks attached to its body
   record.  ``0`` disables WP entirely — the trace records only the
   correct path, the WP chain count is always zero, and the run is
   roughly an order of magnitude faster (measured ~16× on
   ``mcf_r``: see :doc:`architecture` for the full table).
   Useful when you only want a CP trace for a non-speculative
   simulator.

``wpdepth=<insns>``
   Wrong-path *budget* in speculative instructions per branch.
   Default ``64``.  The WP simulator stops the speculative chain as
   soon as ``sim_insns >= wpdepth`` *and* the in-flight WP basic
   block has finished (i.e., the loop won't truncate a BB mid-flight).
   Bigger values give a longer speculative shadow per branch but
   linearly increase runtime — doubling ``wpdepth`` roughly doubles
   the WP work.  Setter rejects non-positive values.

``wpprune=<level>``
   Prune the wrong path for *cold* branches, trading WP coverage for
   speed and a smaller trace.  A degree, default ``0``:

   * ``0`` — no pruning (every mispredictable branch gets a WP walk).
   * ``1`` — skip the WP walk for a branch never seen taken on the
     correct path; for an indirect branch (or return), skip it while
     it is monomorphic (fewer than two distinct observed targets — no
     alternative target to mispredict toward).
   * ``2`` — additionally skip conditionals seen going only one way
     (require both a taken and a not-taken observation).

   Pruning only suppresses the speculative walk; correct-path
   recording, branch directions, and observed targets are unchanged.
   The decision uses each branch's accumulated correct-path history, so
   a branch that is cold early and warms up later starts getting WP
   walks once it warms.

Capture flags
~~~~~~~~~~~~~

.. index::
   single: memdata
   single: regdata

These control how much *dynamic* per-execution data is captured
beyond the static templates.  Templates are mandatory; everything
below is opt-in because it can substantially grow the trace.

``memdata=0`` / ``memdata=1``
   ``0`` (default) records only memory access *addresses* (load and
   store vaddrs).  ``1`` additionally captures the *value* loaded or
   stored, up to 64 bytes per access — the wire format encodes them
   under ``CST_FID_LOAD_DATA*`` / ``CST_FID_STORE_DATA*``.  Needed
   by data-aware consumers (correctness simulators, value-prediction
   research); typical cache-and-prefetcher work doesn't use it.

.. _regdata-semantics:

``regdata=0`` / ``regdata=1``
   ``0`` (default) records no register values.  ``1`` snapshots each
   instruction's *destination* register values immediately after it
   executes, encoded under ``CST_FID_DST_REG*``.  Source values are
   not captured — destinations strictly dominate (they cover every
   architectural write, so consumers can derive any register's value
   at any point from the most recent post-write observation, and
   there are typically fewer destinations than sources per insn).

   Both CP and WP capture the same set of registers (destinations
   only) using the same per-insn callback machinery: when canonical
   insn ``ci``'s pre-exec hook fires, it reads canonical insn
   ``ci-1``'s destination registers from live state (the regfile
   holds ``ci-1``'s post-write values, since ``ci`` hasn't run yet).
   Result: **per-instruction-accurate** destination snapshots for
   every insn whose successor canonical insn pre-execs in the same
   TB / WP fragment.

   The capture point of the *tail* canonical insn of each
   TB / fragment differs by path, because there is no in-flight
   successor inside the same TB to trigger its capture:

   * **CP** captures the tail insn at the *next* TB's first
     ``vcpu_tb_exec`` (between the two TBs, the regfile still
     holds the tail's post-write state).  Per-instruction-accurate
     for every CP insn.
   * **WP** captures the tail insn of each fragment with a live
     post-fragment read.  For a **single-fragment** ``exec_tb``
     this read still lands on the tail's post-write state and is
     per-instruction-accurate.  For a **multi-fragment**
     ``exec_tb`` (mid-TB-branch splits, e.g. MIPS ``teq``), the
     trailing insn of every fragment except the very last one
     reads from a regfile that has already been mutated by later
     fragments in the same ``exec_tb`` — those tail snapshots
     reflect post-everything-in-``exec_tb`` state.  The number
     of WP insns with the post-everything caveat is bounded by
     ``(fragments_per_exec_tb − 1) ≤ 1`` for typical TBs and a
     small multiple for mid-TB-branch ISAs.

``wp_memdata=0`` / ``wp_memdata=1``
   WP-side override for ``memdata``.  Default *inherits* the value
   of ``memdata`` (i.e., the wire-format flag mirrors CP).  Setting
   this to ``0`` regardless of ``memdata`` keeps the WP memop
   *addresses* but drops the per-access *values*; addresses are
   typically what cache and prefetcher simulators need from WP, and
   on speculation-heavy workloads dropping WP data values is one of
   the larger trace-size knobs.  Measured impact on the
   architecture page's mcf table: full data → WP-addresses-only
   takes the trace from 623 MiB to 281 MiB on a 20 M-insn run.
   Setting ``wp_memdata=1`` while ``memdata=0`` is permitted but
   unusual — you'd record values on WP only.

``wp_regdata=0`` / ``wp_regdata=1``
   WP-side override for ``regdata``.  Default inherits from
   ``regdata``.  Skips the per-fragment wide-regfile dump on WP when
   off; in practice this saves substantial runtime on WP-heavy
   workloads since the dump touches every architectural register
   the ISA exposes.

Observability
~~~~~~~~~~~~~

.. index::
   single: histogram
   single: iframe_rate
   single: IFRAME

``histogram=<N>``
   Default ``0`` — disabled.  When ``N > 0``, ``start_trace_segment``
   allocates ``N`` zero-initialized ``Stats`` buckets and
   ``finish_trace_segment`` walks them after printing the segment
   summary.  Each bucket holds the same counters as ``g_stats``
   (CP / WP opcode, branch type, register attribution, memop
   counts) but scoped to one icount slice of width
   ``ceil(span / N)``.  The buckets are mirrored into in
   ``vcpu_tb_exec`` from ``g_current_hist_bucket``.

   The output is a headline table with one row per interval plus
   transposed top-K tables for opcodes / branch types / source
   registers / destination registers (rows are top items; columns
   are intervals).  Use to spot phase shifts within a long
   simpoint segment.

``iframe_rate=<N>``
   Default ``100000`` — IFRAMEs are emitted by default.  When
   ``N > 0``, every Nth observation of a CP template is followed by a
   redundant ``BODY_TAG_IFRAME`` body record encoded against fresh
   template-default baselines (i.e., absolute values).  Decoders use
   these to cross-check that their delta-replay reconstructed the same
   view the writer had — a mismatch raises an error in ``cst_decode``.
   The IFRAME covers the *entire* body record (CP + WP chain + WP
   events), so flagging the CP also IFRAMEs every WP entry attached
   to it.  Setting ``iframe_rate=0`` disables IFRAMEs entirely: the
   resulting trace contains no IFRAME records and loses the
   delta-replay self-check.  Each IFRAME costs roughly the
   absolute-encoded size of the body record it's snapshotting —
   ``cst_audit`` reports the total IFRAME byte count under "IFRAME
   records (validation redundancy)".

Trace metadata
~~~~~~~~~~~~~~

.. index::
   single: program
   single: comment

These don't affect what's captured; they get stamped into the trace
header for downstream tools to identify the run.

``program=<string>``
   Free-form program identifier written into the header.  Defaults
   to none.  The QEMU command line is also recorded automatically
   in the header's ``command`` field — ``program`` is for friendly
   names like ``"mcf_r refrate run0"``.

``comment=<string>``
   Free-form note recorded in the header's ``comment`` field.
   Defaults to none.

.. _canonical-system-config:

Canonical system-mode configuration
-----------------------------------

System-mode tracing — ``qemu-system-<isa>`` driven by
``trace_window=marker:...`` — assumes a specific guest and device
configuration that the tracer's address-space model and owner
attribution depend on.  The knobs are collected here.  Every one is a
no-op for a user-mode (``qemu-<isa>``) run, so nothing in this section
changes a user-mode trace.

**Pin the traced process to one vCPU.**  A trace is scoped to a single
guest address space, and kernel-code per-thread attribution stays
clean only while the traced process remains on one vCPU.  A
compiled-in marker gets this from ``taskset`` / ``isolcpus`` on the
guest workload; :program:`cst_attach` confines an unmodified binary to
one guest CPU by default (``--pin-cpu N`` selects the CPU, ``--no-pin``
disables the confinement).  A process that migrates across vCPUs
anyway draws one ``pin_multivcpu_observed`` warning per segment.

**Boot with kernel page-table isolation off.**  Add ``nopti``
(equivalently ``pti=off``) to the guest kernel command line for x86,
and the analogous switch on other ISAs::

   qemu-system-x86_64 -kernel vmlinuz -initrd rootfs.cpio.gz \
       -append "console=ttyS0 panic=-1 nopti" \
       -plugin ./libchampsim_tracer.so,outfile=run,\
       trace_window=marker:simulation=20000000 ...

With KPTI off the kernel shares each process's address space, so a
kernel basic block is tagged with the owning process's ASID (told
apart from user code by the per-insn ``SYSTEM`` bit) and shared kernel
code deduplicates to a single template instead of one copy per
process.  OS isolation is then modeled *by the consumer* from the
``SYSTEM`` bit rather than baked into the trace — see the *System-mode
traces* discussion in :doc:`concepts`.  When a kernel does run in a
private address space on entry (a PTI-style page-table base), the
``kexc`` option (default on) carries that kernel excursion back to the
user process it was entered from so its synchronous-handler coverage is
kept rather than dropped; see :doc:`reference`.

**Disk-I/O records: virtio-blk with ioeventfd=off and no iothread.**
With ``devio`` on (the default), the tracer brackets each disk request
in the body stream with a ``DEVIO_START`` at issue and a
``DEVIO_STOP`` at completion.  Attach a real disk to exercise it::

   qemu-system-x86_64 -kernel vmlinuz -initrd rootfs.cpio.gz \
       -append "console=ttyS0 panic=-1 nopti" -smp 2 \
       -drive file=scratch.raw,format=raw,if=none,id=d0 \
       -device virtio-blk-pci,drive=d0,ioeventfd=off \
       -plugin ./libchampsim_tracer.so,outfile=run,\
       trace_window=marker:simulation=20000000,devio=1 ...

Each ``DEVIO_START`` is attributed to the process/thread that issued
it.  The guest's virtqueue kick runs in the issuing vCPU's context,
where the tracer queues the owner on that vCPU's bounded kick FIFO; the
block backend's later issue matches the oldest queued kick on that SAME
vCPU's FIFO and stamps its owner (the decoder shows ``attr=exact``).
This is what keeps attribution correct on a multi-vCPU / multi-process
guest, where two processes' disk I/O interleaves in one body stream.
The default virtio *ioeventfd* fast path services the kick without
entering the vCPU context the tracer hooks, so with it on the records
fall back to **positional** attribution (``attr=pos`` — correct for a
single marked process, a guess otherwise).  ``ioeventfd=off`` together
with no dedicated iothread keeps the whole ``kick → blk_aio`` path
observable on the issuing vCPU.  Non-virtio disks (IDE/AHCI) and
kernel-internal I/O always use the positional fallback.  An
initramfs-only guest with no ``-drive`` produces no disk traffic and
therefore no ``DEVIO`` records — the trace is otherwise identical.  See
the ``devio`` option in :doc:`reference` and the record layout in
:doc:`format` (§4.1b).

**Multi-process exact attribution also needs each traced process pinned
to its own vCPU.**  The doorbell's captured owner comes from the same
per-vCPU kernel-mode ownership model every kernel basic block uses (see
:ref:`single-address-space` and the ``--pin-cpu`` guidance above): a
process the guest scheduler migrates mid-syscall leaves its in-flight
block-layer submission on the vCPU it left with no clean owner,
independent of how the doorbell is correlated.  Two
CONCURRENT marked processes issuing disk I/O therefore want the same
``taskset``/``isolcpus`` (or ``sched_setaffinity`` inside the workload)
confinement a single pinned process already needs — not merely
``ioeventfd=off`` — to stay inside the clean-attribution envelope.

**Physical-page records (optional).**  ``physaddr=1`` adds the physical
**page** base of every load and store via the ``CST_FID_LOAD_PPAGE`` /
``CST_FID_STORE_PPAGE`` families, letting a consumer rebuild the full
physical address as ``ppage | (vaddr & 0xFFF)``.  It is off by default,
forced off in user mode (no virtual-to-physical translation exists
there), and records a page's mapping only on first touch, so a
physaddr-free or user-mode trace is byte-identical regardless.  See the
``physaddr`` option in :doc:`reference`.

**x86-64 kernel-thread identity (optional).**  ``curtask_off=0x<off>``
declares the traced kernel build's per-CPU offset of ``current_task``,
letting the x86-64 target name the running task at kernel privilege
for tasks with no TLS base — kernel threads, the per-CPU idle tasks, a
TLS-less workload's kernel excursions — so those split into per-task
strands instead of collapsing onto the id minted for the value 0.  The
offset is decided at kernel link time and **differs per build**:
derive it from the image you boot (percpu symbol ``current_task``, or
``pcpu_hot`` — ``current_task`` is its first member — on
``6.2 <= v < 6.14``) via the kernel's ``System.map``, ``nm`` on an
unstripped ``vmlinux``, or the guest's own ``/proc/kallsyms``; the
validator's ``derive_curtask`` module automates all three.  Without
the option kernel identity is unchanged (the collapse is the
documented degraded contract — see :ref:`limits-kernel-strand`);
x86-64 system mode only, ignored elsewhere with a warning.

**Determinism.**  The reproducibility flags in
:ref:`reproducibility-flags` (host CPU pin, host-ASLR disable,
environment scrub) apply to the ``qemu-system`` process itself the same
way they apply to user-mode QEMU; system-mode runs additionally benefit
from QEMU's record/replay machinery (``docs/system/replay.rst``), which
is system-mode only.

Common configurations
---------------------

Recipes for the typical research targets.  Each line is a single
``-plugin`` invocation; replace ``./prog`` with your workload.

**Cache + prefetcher trace for ChampSim-style consumers**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,memdata=0,wp_memdata=0 \
                 ./prog

Captures CP and WP load / store *addresses* (no values).  WP
memops are kept (cache-pollution stream) but their values are
dropped — the dominant trace-size knob on speculation-heavy code.

**Branch-prediction trace**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,wpdepth=128,memdata=0,regdata=0 \
                 ./prog

Smaller still: no memory data, no register data, but every branch
in the trace has both its actual outcome and the wrong-path
shadow used by mispredict-penalty studies.  ``wpdepth=128``
lengthens the speculative window when you want to see further
into the alternate path.

**Value-prediction / data-aware trace**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,memdata=1,regdata=1 \
                 ./prog

Most expensive configuration: every memop value and every
destination-register write is recorded.  Trace size grows with
the workload's data footprint; enable per-member compression
(see the ``compress=`` flag above) when running long workloads.

**Long-workload simpoint capture**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,\
   trace_window=simpoint:file=run.simpts+interval=100000000+\
   warmup=100000000+simulation=100000000 \
                 ./prog

One per-simpoint ``.cst`` file with 100 M warmup + 100 M evaluation
instructions per segment.  Drives ChampSim-style sampled simulation
on multi-billion-instruction workloads in tractable trace volume.

**Symbol-triggered capture (skip startup, trace from main)**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=1,\
   trace_window=symbol:name=main+occurrence=1+simulation=20000000 \
                 ./prog

Trace opens the first time ``main`` is entered as a TB and captures
20 M architectural instructions.  Useful when the run's startup
icount is workload-dependent and a fixed ``start=<icount>`` would
miss the steady-state region.

**CP-only trace for a non-speculative simulator**

.. code-block:: console

   $ qemu-x86_64 -plugin ./libchampsim_tracer.so,outfile=run,wp=0,memdata=0 \
                 ./prog

Smallest, fastest configuration.  No WP chain, no memory data —
just the architectural correct path with addresses.

Output files and stderr
-----------------------

Three files land beside the basename:

* ``<outfile>.cst`` — the binary trace.
* ``<outfile>.unknown_warnings.log`` — Capstone-flagged instructions the
  generic-opcode mapper didn't recognize.  Empty on a clean run.
* ``stderr`` — segment lifecycle (``starting segment``, 10 % progress
  ticks, ``finished segment``) plus a final statistics summary
  containing CP/WP totals, branch-type breakdown, opcode usage, and
  register attribution.

Reading the trace
-----------------

``cst_decode`` (built next to the plugin) emits a greppable,
``objdump``-style dump:

.. code-block:: console

   $ build/contrib/plugins/cst_decode run.cst | head
   ; cst_decode disassembly
   ; version=0x1D545343
   ; isa=x86_64
   ; flags=MEM_DATA REG_DATA
   ; templates=7979
   ...
   ; ----- BB 3 entry pc=0x734e6b076540 insns=2 seq=1 tid=0 asid=0 branch=taken target=0x734e6b0771d0 -----
   0x734e6b076540: 48 89 e7                 mov     %sp -> %gp5[0x734e595feca0/w8]
   0x734e6b076543: e8 88 0c 00 00           call    %sp, $0x734e6b0771d0 -> %sp[0x734e595fec98/w8]  ...

Each line is self-contained — pipe it through ``grep`` by PC,
mnemonic, register reference (``%gp1`` etc.), memop pattern
(``ld[`` / ``st[``), branch-target comment (``# 0x``), or the
``; ----- BB`` boundary markers.  See :doc:`decoder` for the
full column reference, the ``--templates-only`` and ``--objdump``
flags, and the block-formatted ``--format=legacy`` output.

A byte-budget audit (helpful when tuning trace size) is one command:

.. code-block:: console

   $ build/contrib/plugins/cst_audit run.cst
     profile: exec_cp=213099 exec_wp=2473849  mem-insns=14631 addr-insns=5306  pat[none/reg/irr/rand]=32999/6530/160/77
   === ON DISK ===
     container (.cst)                               105.69 MiB

   === MEMBER SIZES (uncompressed) ===
     TOTAL uncompressed                             105.68 MiB  100.00%
     HEADER member                                    1.31 MiB    1.24%  [     7,979 tmpl, avg  172.6 B]
     BODY member (records)                          104.37 MiB   98.76%

   === HEADER BREAKDOWN (1.31 MiB) ===
     preamble + encoding maps                        23.70 KiB    1.76%
     BB info (id/pc/n/ft/targets/sym)               200.59 KiB   14.92%
     instruction descriptors                        659.84 KiB   49.07%
     dependency sub-blocks                          103.22 KiB    7.68%
     template profile block                         345.52 KiB   25.70%

   === BODY BREAKDOWN (104.37 MiB) ===
     CP field-delta section                          63.71 MiB   61.04%
     WP chain envelope (incl. inner)                 39.75 MiB   38.08%
     WP events                                      470.77 KiB    0.44%
     ...

The report distinguishes the on-disk ``.cst`` container size (the
tar-of-compressed-members blob) from the post-decompression
``TOTAL uncompressed`` figure that the breakdowns sum to.

For both tools' full surface see :doc:`decoder`.  For the
self-checking workload harness that exercises the plugin under
controlled inputs and verifies the resulting trace, see
:doc:`validator`.

.. _reproducibility:

Reproducibility
---------------

The trace is deterministic in the following sense: given the same
guest binary, the same QEMU command line, the same plugin flags,
and the same plugin build, two runs produce body streams that are
*architecturally identical* — every basic block invoked matches across runs.
In practice two ``.cst`` files from back-to-back runs differ due to 
non-determinism in the guest's address space layout, random bytes,
host scheduling, and other factors. The flags below reduce this non-determinism
and make runs more closely match each other, but they don't eliminate all sources of divergence.

.. _reproducibility-flags:

Flags that reduce non-determinism
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Non-determinism enters a user-mode QEMU run through three layers,
each with its own knob.  Set all of them when you want runs that
match each other.

.. list-table::
   :header-rows: 1
   :widths: 18 30 52

   * - Layer
     - Knob
     - What it pins / what's left unpinned without it
   * - Guest randomness
     - ``-seed N`` on the QEMU binary (env ``QEMU_RAND_SEED``)
     - Switches ``qemu_guest_getrandom`` to a deterministic
       Mersenne Twister seeded by ``N``.  Backs the ``AT_RANDOM``
       16-byte auxv entry that glibc reads for the stack canary,
       the pointer-mangling key (``__pointer_chk_guard``), and
       several internal hash-table seeds, plus any guest call to
       ``getrandom(2)``.  Without it every run gets fresh
       cryptographic-random bytes here.
   * - Guest base address
     - ``-B address`` (env ``QEMU_GUEST_BASE``)
     - Fixes the host↔guest virtual-address offset so PIE
       binaries and the dynamic linker land at the same guest
       VAs every run.  Without it, ``probe_guest_base`` /
       ``pgb_dynamic`` derives the base from the host's
       ``sbrk(0)`` and ``/proc/self/maps`` — both subject to
       host ASLR — so every guest pointer that survives a
       run-to-run comparison shifts.
   * - Guest mmap layout
     - ``-R size`` (env ``QEMU_RESERVED_VA``)
     - Pre-allocates a reserved guest-VA window of ``size``
       bytes and routes every guest ``mmap`` through a
       deterministic linear walker
       (``mmap_find_vma_reserved``).  Without it each guest
       ``mmap`` is forwarded to the host kernel, which applies
       host ASLR per call — so glibc / vDSO / ld.so end up at
       different guest addresses each run.  ``-R 8G`` is enough
       for typical SPEC-class workloads on a 64-bit guest.
   * - Host scheduling
     - ``taskset -c 0`` on the QEMU command
     - Pins the QEMU process to one host CPU.  Removes a class
       of TCG-translation-cache timing variance.  Does not
       affect what the guest sees of itself.
   * - Host ASLR
     - ``setarch -R`` on the QEMU command
     - Disables host-side ASLR for the QEMU process itself.
       Belt-and-braces complement to ``-B`` / ``-R``: even when
       the guest layout is fully pinned, host-side ASLR can
       shift where QEMU's own libraries land, which can affect
       ``pgb_dynamic``'s fallback search when ``-B`` is *not*
       set.  With ``-B`` set this knob has no observable effect
       on the trace, but it costs nothing to leave on.
   * - Inherited environment
     - ``env -i HOME=/tmp PATH=/usr/bin LANG=C``
     - Strips inherited environment variables.  Different shell
       environments leave different bytes in the guest's
       startup stack via ``envp`` and ``auxv``, which feeds back
       into glibc-initialised data structures the workload may
       later touch.

Knobs that exist but do *not* belong here:

* ``-d ...`` (logging) and ``--icount`` (system-mode only) do
  not change what the user-mode plugin observes.
* QEMU's full record/replay machinery
  (``-record`` / ``-replay``, documented in the upstream
  ``docs/system/replay.rst``) is **system-mode only** and cannot
  be combined with user-mode emulation.

Residual sources after all knobs are set
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Even with the full flag set above, four sources are not
controlled by any QEMU flag:

* **Host-passthrough syscalls.**  ``gettimeofday``,
  ``clock_gettime``, ``time``, ``getpid``, ``gettid`` and reads
  from ``/proc/self/*`` go straight to the host.  Workloads
  that read wall-clock time or hash by PID will diverge.  The
  tracer records the divergence faithfully; pin the workload's
  clock at the workload level if bit-stability is required.
* **Pre-segment icount drift.**  When a segment opens at a
  fixed ``icount=N``, every guest instruction *before* the
  segment counts toward ``N`` — including the dynamic linker
  and glibc startup.  Glibc init's instruction count is
  sensitive to ``AT_RANDOM``, library load addresses, and heap
  layout, so without all three of ``-seed`` / ``-B`` / ``-R``,
  the pre-segment count drifts by a few thousand instructions
  per run, and the segment ends up covering a slightly
  different *slice* of the workload's user code.  The window
  length stays exact; the slice it covers does not.  Observed
  manifestation: ``exec_cp`` differs by ~0.01 % across re-runs
  of the same SPEC binary at the same icount window.  Setting
  all three layer-1 knobs pins glibc init byte-for-byte and
  removes the drift.
* **Multi-vCPU interleaving.**  Multi-threaded guest workloads
  can interleave vCPUs differently across runs.  See
  :ref:`multi-vcpu` in the architecture doc.
* **WP reads of uninitialised data.**  The wrong-path simulator
  follows branch directions the program would not normally
  take, so it can dereference a stack frame or malloc chunk
  while it still holds residue from a prior function call.
  The bytes there are whatever the OS / glibc / a prior caller
  happened to leave behind — they are not bound by the
  program's data-flow.  Aggregate WP counts (entries, total
  instructions, address-set coverage) remain reproducible; a
  small number of WP fragments' value bytes do not.  See
  :doc:`limitations` for the detailed mechanism and why this is
  fundamentally not fixable from the plugin side.

Cross-host reproducibility holds when the above-listed
controllable sources are pinned — the same guest binary
produces the same trace on two different hosts running the
same QEMU+plugin build.  Cross-QEMU-version reproducibility is
*not* guaranteed: if the QEMU base moves to a different
upstream commit, the TB carving heuristics may shift, which
renumbers ``template_id`` in the dictionary.  The body's
architectural content stays the same.

Recommended invocation for maximum reproducibility
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ env -i HOME=/tmp PATH=/usr/bin LANG=C \
     taskset -c 0 setarch -R \
     qemu-x86_64 -seed 42 -B 0x40000000 -R 8G \
       -plugin ./libchampsim_tracer.so,outfile=run,wp=1,memdata=1,regdata=1,\
                trace_window=icount:start=0+stop=20000000 \
       ./your_workload

With all six knobs in place on the same host and same QEMU +
plugin build, the CP path of a single-vCPU workload is
reproducible byte-for-byte except for the residual sources
listed above.  Drop any of the layer-1 knobs (``-seed`` /
``-B`` / ``-R``) and the *content* of any windowed segment
shifts via the pre-segment-icount-drift mechanism — even when
the workload itself reads no clocks and uses no randomness.

Feeding ChampSim
----------------

ChampSim does not consume the ``.cst`` format directly —
ChampSim's stock trace path takes its own ``instr_t``-shaped binary.
A ``.cst`` → ChampSim adapter is the consumer's responsibility:
the trace exposes everything ChampSim needs (per-instruction
PC, branch type and outcome, load/store addresses, optional values,
wrong-path chain), but the marshalling of those fields into
ChampSim's expected layout lives outside this repository.

The recommended consumer pattern is:

1. Iterate body entries with ``cst_decode --format=disasm`` (one
   line per architectural instruction, easy to grep) or via a
   custom C++ consumer linked against ``libcst_tools_common`` — the
   compiled static library the offline tools share, built from
   ``cst_format.cc`` and ``cst_decode.cc`` with its headers in
   ``contrib/plugins/champsim_tracer/tools/``.
2. Convert per-record fields into the simulator's expected
   structure on the fly.  Templates are loaded once at the start
   of the trace and kept in memory; body entries stream past one
   at a time so memory stays bounded regardless of trace length.

Building this documentation
---------------------------

The site you are reading is a Sphinx project under
``contrib/plugins/champsim_tracer/docs/``.  Two output formats are
supported.

HTML (the default)
~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ pip install sphinx furo myst-parser
   $ make -C contrib/plugins/champsim_tracer/docs html
   # open _build/html/index.html

Output lands in
``contrib/plugins/champsim_tracer/docs/_build/html/``.  No TeX
install is required.

PDF (offline / portable)
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ # Same Python deps as HTML, plus a TeX install with FreeSerif:
   $ sudo apt install texlive-xetex texlive-latex-recommended \
                      texlive-fonts-recommended fonts-freefont-otf \
                      latexmk
   $ make -C contrib/plugins/champsim_tracer/docs latexpdf
   # PDF: contrib/plugins/champsim_tracer/docs/_build/latex/champsim_tracer.pdf

.. note::

   ``fonts-freefont-otf`` is required separately on
   Debian/Ubuntu — Sphinx's ``xelatex`` template selects FreeSerif
   as the default body face, and ``texlive-fonts-recommended``
   alone does not include it.  Without it the build aborts at
   ``fontspec Error: The font "FreeSerif" cannot be found``.

``make pdf`` is an alias.  The build uses XeLaTeX (driven by
``latexmk``) so the output handles UTF-8 in code blocks and the
encoding-map names without surprise.  Paper size is letter; flip
``latex_elements["papersize"]`` in ``conf.py`` to ``"a4paper"`` for
A4.

The GitHub Actions workflow at
``.github/workflows/champsim-tracer-docs.yml`` builds the HTML on
each push to ``champsim-trace`` that touches the docs and deploys
it to Pages.  PDF is *not* built in CI; run ``make pdf`` locally
when a PDF is needed.
