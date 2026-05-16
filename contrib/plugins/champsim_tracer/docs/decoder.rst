Decoder and audit tools
=======================

Two offline consumers of a ``.cst`` trace, both C++ binaries built
alongside the plugin.  ``ninja contrib-plugins`` produces them in
``build/contrib/plugins/`` next to the ``.so`` itself.  Neither tool
needs the QEMU plugin runtime — they read the wire format directly
from the file.

* :ref:`cst_decode <decoder-cc>` is the default decoder.  It emits an
  objdump-style disassembly to stdout, with one line per architectural
  instruction.  ``--templates-only`` suppresses the body walk and emits
  one PC-sorted line per static template entry — the analogue of
  ``objdump -d`` over the captured templates.  ``--objdump`` adds a
  side-by-side Capstone disassembly column so the generic-opcode line
  can be cross-checked against ``objdump`` output.

* :ref:`cst_audit <audit-cc>` prints a byte-budget breakdown of
  where bytes go (header, templates, CP body, WP body, field-delta
  records, ...).  Use it when tuning trace size or diagnosing where
  unexpected bytes accumulated.

.. _decoder-cc:

cst_decode
----------

.. index::
   single: cst_decode
   single: --templates-only
   single: --objdump
   single: --show-deps
   single: --show-lanes

Built by the same ``ninja contrib-plugins`` invocation that builds
the plugin shared object.  Lands in
``build/contrib/plugins/cst_decode``.

.. code-block:: console

   $ build/contrib/plugins/cst_decode trace.cst > trace.disasm
   $ build/contrib/plugins/cst_decode --templates-only trace.cst > trace.t.disasm
   $ build/contrib/plugins/cst_decode --objdump trace.cst > trace.objdump.disasm

Output format
~~~~~~~~~~~~~

The output starts with a ``;``-prefixed header banner that
records the trace's metadata (magic, ISA, command line,
datetime, feature flags, segment window, template count).  Body
records follow, grouped by basic block with one architectural
instruction per line in an ``objdump -d``-style layout.

Sample, with ``wp=1,memdata=1,regdata=1`` capture flags:

.. code-block:: text

   ; cst_decode disassembly
   ; version=0x1C545343
   ; isa=x86_64
   ; command=qemu-x86_64 -seed 42 -plugin libchampsim_tracer.so,outfile=run,...
   ; datetime=2026-05-10 16:11:23
   ; flags=MEM_DATA REG_DATA
   ; start_insn=0 warmup_insns=0 total_target_insns=10000
   ; templates=31

   ; ----- BB 3 entry pc=0x401740 insns=12 seq=1 tid=0 -----
   0x000000401740 <_start+0x0>: f3 0f 1e fa              nop
   0x000000401744 <_start+0x4>: 31 ed                    xor     %fpr -> %fpr[0x0], %flags[0x202], %mflags[-]
   0x000000401749 <_start+0x9>: 5e                       pop     %sp -> %gp4[0x1], %sp[0x78b25adff138]  ld(0x78b25adff130)=0x1
   0x000000401751 <_start+0x11>: 50                       push    %gp0, %sp -> %sp[0x78b25adff128]  st(0x78b25adff128)=0x0
   0x00000040175f <_start+0x1f>: 67 e8 eb 25 00 00        jmp     $0x403d50, %sp, %ip -> %sp[0x78b25adff118], %ip[0x403d50]  st(0x78b25adff118)=0x401765
   ; ----- BB 5 entry pc=0x403d50 insns=22 seq=2 tid=0 -----
   ...
   0x000000403d99 <__libc_start_main_impl+0x49>: 75 f5                    jcc     $0x403d90, %flags, %ip -> %ip[0x403d90]  # 0x403d9b <__libc_start_main_impl>

Per-instruction line columns:

* PC, 12 hex digits zero-padded.
* Optional ``<symbol+offset>`` annotation when the captured
  template named the TB's owning symbol.
* Raw instruction bytes from the template.
* Generic-opcode mnemonic (``add`` / ``fmul`` / ``jmp`` / …).
* Operand list in a fake AT&T syntax: register references print
  as ``%gp0`` / ``%flags`` / ``%ip``, immediates as ``$0x...``,
  destinations are separated from sources by ``->`` so each
  side of a read-modify-write is visible at a glance.

The branch-mnemonic flavour (``jmp`` / ``jcc`` / ``jmpr`` /
``ret`` / ``syscall``) comes from the trace's own
``branch_type`` encoding map — looked up by the wire-format
integer id and matched against the stable string name — rather
than a compile-time enum.  Same for register and opcode names:
the decoder's only source of truth is the encoding map the
writer stamped into the trace header.

Captured per-instruction data is folded into the operand line:

* ``%dst[<value>]`` — destination register post-execution
  snapshot (when ``regdata=1`` was set during capture).
* ``%mflags[<bits>]`` — synthetic canonical-flags register
  rendered as a bit-string of set flags drawn from
  ``Z`` / ``N`` / ``C`` / ``V`` / ``P``, in that order, or ``-``
  when no flag is set.  Appears alongside ``%flags`` on ISAs with
  an integer flags register (x86, AArch64); spares consumers
  from per-ISA bit-shuffle math.  RISC-V and MIPS templates do
  not carry this slot.
* ``ld(<addr>)=<value>`` / ``st(<addr>)=<value>`` — memory
  operation effective address with the loaded / stored value
  (when ``memdata=1``), or just the address ``ld(<addr>)`` /
  ``st(<addr>)`` (when ``memdata=0``).  When ``memdata=1`` the
  ``=<value>`` suffix is always present, including for zero
  values, so the absence of ``=`` unambiguously means
  ``memdata`` was not captured.
* ``# <target> <symbol+offset>`` trailing comment — branch
  target captured from the ``REG_IP`` snapshot post-execution,
  with the matching symbol name when known.

Basic-block boundaries are marked by a single
``; ----- BB <template_id> entry pc=<pc> insns=<n> seq=<seq>
tid=<n> -----`` separator line (note the ``;`` prefix so it
groups with the header comments).  Wrong-path entries are
attached to their parent CP entry's WP chain and rendered with
the same per-instruction format under a separate
``; ..... wp[k] BB <id> n_insns=<n> [status=...] -----``
separator (the ``status=FAULT@insn<n>`` suffix appears when the
WP simulator hit a fault on a non-terminating instruction
inside that chain entry).

``--templates-only``
   Skip the body stream entirely and emit exactly one line per
   static template instruction, sorted by PC.  No basic-block
   boundary markers, no per-execution dynamic values — just the
   captured architectural shape.  This is the analogue of running
   ``objdump -d`` over the binary, restricted to PCs that the
   guest actually executed during the trace.

``--objdump``
   Add a side-by-side Capstone-disassembly column to each printed
   line so the generic-opcode rendering can be cross-checked
   against the canonical ISA mnemonic.  Combines with
   ``--templates-only`` (templates side-by-side with Capstone) and
   with the default body walk (per-execution lines side-by-side
   with Capstone, but only the static template half is shown on
   the Capstone side — ``objdump`` has no notion of the captured
   dynamic values).  Capstone is taken from the bundled
   ``subprojects/capstone`` so both sides come from the same
   build the plugin links against.

``--show-deps``
   Append a trailing ``; deps:`` annotation giving the
   intra-instruction dependency edges: per destination register and
   per store-data slot, the set of inputs (source regs, load slots,
   immediate) it depends on, plus the ``laddr``/``saddr``
   address-input sets for each memop.  Coarse all-to-all dep masks
   are refined to the precise edges by excluding address-only srcs
   (they reach the dst transitively through the memop, already shown
   as ``laddr``/``saddr``).

``--show-lanes``
   Annotate every vector operand with its participating lane set,
   collapsing consecutive lanes into ranges (``%v0{0..3,6}``).
   Applies to source/destination registers, load and store memop
   slots, and — together with ``--show-deps`` — the dependency
   annotation, where an input is shown feeding a destination only on
   the lanes their masks share.  This is the reference
   implementation of the wire format's lane-granularity dependency
   resolution (see :doc:`format`, *Vector lane masks*): e.g.
   ``pinsrd $3`` renders ``ld[%sp](...){3}, $0x3 -> %v0{3}`` with
   ``deps: %v0{3}=[ld0{3},imm]`` — lane 3 from the load only, the
   pass-through ``%v0{0..2}`` correctly excluded.  Scalar traces are
   byte-identical with and without the flag.

.. _audit-cc:

cst_audit
---------

.. index::
   single: cst_audit
   single: byte budget

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst

Prints a byte-budget table covering top-level sections, body
breakdown, field-delta record breakdown, and entry / insn totals.
Hands you a hard byte count (every byte produced by the writer is
counted exactly once and the section totals add up to the file
size), so the workflow when tuning trace size is:

1. Run ``cst_audit`` on a baseline trace.
2. Toggle a writer flag (``wp_memdata=0``, ``wp_regdata=0``,
   ``memdata=0``).
3. Re-run.  A flag that pays off shows up as a line item shrinking
   by an order of magnitude.

Sample output:

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
   FILE                                     12.34 MiB  100.00%

   === TOP-LEVEL SECTIONS ===
     HEADER                                  6.18 KiB    0.05%
     TEMPLATES                              412.30 KiB    3.27%  [    3,405 tmpl, avg  104.6 B]
     BODY                                    11.94 MiB   96.66%
     TRAILER                                      64 B    0.00%

   === BODY BREAKDOWN (11.94 MiB) ===
     CP entry framing                        71.78 KiB    0.59%  [   35,857 entry, avg    2.0 B]
     CP field-delta section                 185.99 KiB    1.52%  [   35,857 entry, avg    5.3 B]
     ...
     IFRAME records (validation redundancy)  80.34 KiB    0.66%  [      388 iframe, avg  212.0 B]

The ``IFRAME records`` line appears only on traces produced with
``iframe_rate>0``; those bytes are pure validation overhead and
disappear when the feature is off.

Validating a trace
------------------

A ``.cst`` file is well-formed if all of the following hold; the
two C++ tools collectively check every one:

1. **The trailer magic matches the header magic.**
   ``cst_decode`` checks this first; mismatch is a fatal error.
2. **The body's offset and length match the trailer's offsets and
   the header's parsed length.**  ``cst_decode`` raises
   ``header/body offset mismatch`` if not.
3. **The body's footer ENTRY count matches the body walker's
   observation.**  ``cst_decode`` raises
   ``footer entry-count mismatch`` if not.
4. **Every IFRAME (when present) reproduces the same per-entry
   shape as its preceding ENTRY.**  See "IFRAME validation"
   below.
5. **Every section's byte budget rolls up to the file size.**
   ``cst_audit`` verifies this — the printed top-level totals
   (HEADER + TEMPLATES + BODY + TRAILER) sum to ``FILE`` exactly.
   A negative line item or a non-100% rollup is a writer bug.

The recommended validation workflow:

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
   FILE  ...  100.00%       # totals must sum to 100%

   $ build/contrib/plugins/cst_decode trace.cst > /dev/null
   # exit status 0 means the body walker accepted every record

The combination is a cheap end-to-end correctness check: the audit
sums all bytes, and the decoder replays the body's delta stream
end-to-end.

IFRAME validation
~~~~~~~~~~~~~~~~~

.. index::
   single: IFRAME validation
   single: BODY_TAG_IFRAME

When a trace was produced with ``iframe_rate=N`` the writer follows
selected ``BODY_TAG_ENTRY`` records with a redundant ``BODY_TAG_IFRAME``
record carrying the same payload encoded against template-default
baselines (so every value is absolute).  ``cst_decode`` transparently
walks each IFRAME against fresh empty overlays and the body walker
verifies its dyn-param and reg-snap counts match the preceding ENTRY;
mismatches raise an error.  IFRAMEs are not surfaced as separate
``BODY_TAG_ENTRY`` records — ``cst_decode`` reports a body-entry
count that matches the writer's ``num_entries`` footer field.

When you want maximum confidence in a fresh trace (e.g. before
checking it into a paper's artifact repository), produce it with
``iframe_rate=10000`` (every 10000th observation gets a
verification record) and decode it with ``cst_decode`` — the
decoder will fail loudly if any IFRAME's recorded view doesn't
match its delta replay's reconstruction of the matching ENTRY.
Drop the IFRAME flag once you've gotten a clean decode, and the
production trace is byte-identical to one produced without IFRAME
generation.

mnemonic survey / audit
-----------------------

Two helpers tied to the disassembly classification step rather than
the wire format:

* ``champsim_tracer_mnemonic_survey.py`` walks a workload, records
  every Capstone mnemonic it sees, and prints frequency counts.
  Useful when adding ISA support: it tells you which mnemonics need
  rows in ``champsim_tracer_mnemonic_tables.c``.

* ``champsim_tracer_mnemonic_audit.py`` diffs the union of seen
  mnemonics against the static classification table and reports any
  unclassified ones.  Run after adding a new opcode or ISA to confirm
  the table covers the workload.

Both run against an existing trace and don't require a fresh QEMU
invocation.
