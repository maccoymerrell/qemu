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
  records, thread-switch records, per-thread REGFILE records, ...).
  Use it when tuning trace size or diagnosing where unexpected bytes
  accumulated.

.. _decoder-cc:

cst_decode
----------

.. index::
   single: cst_decode
   single: --format
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
datetime, feature flags, segment window, SimPoint weight,
template count).  Body records follow, grouped by basic block
with one architectural instruction per line in an
``objdump -d``-style layout.

Sample, with ``wp=1,memdata=1,regdata=1`` capture flags:

.. code-block:: text

   ; cst_decode disassembly
   ; version=0x1D545343
   ; isa=x86_64
   ; command=qemu-x86_64 -seed 42 -plugin libchampsim_tracer.so,outfile=run,...
   ; datetime=2026-05-10 16:11:23
   ; flags=MEM_DATA REG_DATA
   ; start_insn=0 warmup_insns=0 total_target_insns=10000
   ; simpoint_weight=1
   ; templates=31

   ; ----- BB 3 entry pc=0x401740 insns=12 seq=1 tid=0 -----
   ; profile: exec_cp=1 exec_wp=0
   ; target[0]: pc=0x403d50 taken_cp=1 nottaken_cp=0 taken_wp=0 nottaken_wp=0
   0x000000401740 <_start+0x0>: f3 0f 1e fa              nop
   0x000000401744 <_start+0x4>: 31 ed                    xor     %fpr -> %fpr[0x0], %flags[0x202], %mflags[-]
   0x000000401749 <_start+0x9>: 5e                       pop     %sp -> %gp4[0x1], %sp[0x78b25adff138]  ld(0x78b25adff130)=0x1  prof: memops_cp=1 pat_cp=CST_PAT_REGULAR cp=[0x78b25adff130-0x78b25adff130]
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

The run-aggregated profile block (see :doc:`concepts`,
*Run-aggregated profile*) is rendered **as part of the BB it
belongs to**, never as a separate dump.  Two BB-level lines follow
each ``; ----- BB ... -----`` separator:

* ``; profile: exec_cp=<n> exec_wp=<n>`` — the BB's run totals.
* ``; target[<k>]: pc=<edge> taken_cp=<n> nottaken_cp=<n>
  taken_wp=<n> nottaken_wp=<n>`` — one line per terminal-branch
  taken edge (``k`` indexes the template's target list; the
  not-taken edge is the BB's ``fall_through``).

Per-instruction profile rides **inline on the instruction's own
line** as a trailing ``prof: <k>=<v> …`` tag — never clustered at
the block header.  Only the meaningful fields appear (``memops_cp``
/ ``memops_wp``, ``pat_cp`` / ``pat_wp`` access-pattern class,
``addr_cp`` / ``addr_wp`` data-is-address, ``cp=[lo-hi]`` /
``wp=[lo-hi]`` effective-address bounds); an instruction with no
mem-ops and a ``NONE`` pattern carries no tag at all.  The
``; ``-comment prefix on the BB-level lines keeps them grouping
with the header in greppable output; the same data appears in the
``--format=legacy`` and ``--templates-only`` views without the
comment prefix.

``--format=disasm`` / ``--format=legacy``
   Select the output mode; ``disasm`` is the default and produces
   the ``objdump -d``-style layout described above.
   ``--format=legacy`` (also spelled ``--legacy``) emits the older
   line-oriented dump — a flat ``<srcs> -> <dsts>`` per-instruction
   layout with the encoding maps, templates, and body observations
   printed without the ``; ``-comment prefix.  It is byte-identical
   to ``champsim_tracer_decode.py``'s ``render_text_streaming``
   output, retained so trace-diffing scripts that predate the C++
   decoder keep working.  ``--format=legacy`` is incompatible with
   ``--templates-only``.

``--templates-only``
   Skip the body stream and emit the static template dictionary,
   one block per true basic block: a ``BB<id> <pc> <symbol>``
   header, the BB-level profile / target lines, then one line per
   template instruction (PC-ordered) with its inline ``prof:`` tag.
   No per-execution dynamic values — just the captured
   architectural shape plus the run-aggregated profile.  The
   analogue of ``objdump -d`` over the binary, restricted to PCs
   the guest actually executed.

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

Prints a byte-budget table: an **on-disk** line (the container's
actual ``.cst`` size, plus the compressed body member's size and
codec ratio when the body is compressed), member sizes, a **header
breakdown**, a body breakdown, the field-delta record breakdown,
and entry / insn totals.  Every byte the writer produced is counted
exactly once and each section sums to its parent (a
``[rollup 100.00%]`` line asserts the header reconciles), so the
workflow when tuning trace size is:

1. Run ``cst_audit`` on a baseline trace.
2. Toggle a writer flag (``wp_memdata=0``, ``wp_regdata=0``,
   ``memdata=0``).
3. Re-run.  A flag that pays off shows up as a line item shrinking
   by an order of magnitude.

Sample output (abridged):

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
   === ON DISK ===
     container (.cst)                          12.04 KiB

   === MEMBER SIZES (uncompressed) ===
     TOTAL uncompressed                       28.68 KiB  100.00%
     HEADER member                            25.93 KiB   90.41%  [   31 tmpl, avg  856.4 B]
     BODY member (records)                     2.75 KiB    9.59%

   === HEADER BREAKDOWN (25.93 KiB) ===
     preamble + encoding maps                 19.15 KiB   73.87%
     section framing (counts+lengths)              61 B    0.23%
     BB info (id/pc/n/ft/targets/sym)             666 B    2.51%  [   31 tmpl, avg  21.5 B]
     instruction descriptors                   3.94 KiB   15.19%  [   31 tmpl, avg 130.1 B]
     dependency sub-blocks                        595 B    2.24%  [   31 tmpl, avg  19.2 B]
     template profile block                    1.54 KiB    5.96%  [   31 tmpl, avg  51.0 B]
       sum                                    25.93 KiB  100.00%  [rollup 100.00%]

   === BODY BREAKDOWN (2.75 KiB) ===
     CP entry framing                              42 B    1.49%  [   21 entry, avg   2.0 B]
     CP field-delta section                       892 B   31.68%  [   21 entry, avg  42.5 B]
     thread-switch records                          0 B    0.00%  [    0 switch]
     ...
     IFRAME records (validation redundancy)         0 B    0.00%
     REGFILE records (per-thread initial state)    96 B    3.41%  [    1 regfile]

The **HEADER BREAKDOWN** attributes every header byte to a
template-block group, so the cost of each piece of static metadata
is visible: ``BB info`` (the per-BB header — id, start PC, insn
count, ``fall_through``, the terminal-branch ``n_targets`` / target
list, symbol), ``instruction descriptors``, optional ``dependency
sub-blocks``, and the run-aggregated ``template profile block``.
The **BODY BREAKDOWN** likewise covers every body record kind: CP
and WP entry framing and field-delta sections, WP events,
``thread-switch records`` (one per ``BODY_TAG_THREAD_SWITCH``) and
``REGFILE records`` (one ``BODY_TAG_REGFILE`` per thread, carrying
that thread's initial regfile snapshot), the ``IFRAME records``
line, and the body terminator.  The ``IFRAME records`` line appears
only on traces produced with ``iframe_rate>0``; those bytes are
pure validation overhead and disappear when the feature is off.

Validating a trace
------------------

A ``.cst`` file is a ustar archive with two members — a
magic-bracketed header member and a magic-bracketed body member.
It is well-formed if all of the following hold; the two C++ tools
collectively check every one:

1. **The header member begins with ``CST_MAGIC``.**  Opening the
   trace parses the header member and raises ``Bad header magic``
   if the leading ``u32`` does not equal ``CST_MAGIC``.
2. **The body member is bracketed by ``CST_MAGIC``.**  The leading
   ``u32`` of the body member must equal ``CST_MAGIC`` — opening it
   raises ``Bad body leading magic`` otherwise — and its trailing
   ``u32`` must equal ``CST_MAGIC``, raising
   ``body member truncated (bad trailing magic)`` otherwise.
3. **The body's footer ENTRY count matches the body walker's
   observation.**  ``cst_decode`` raises
   ``Footer entry-count mismatch`` if the ``BODY_TAG_END`` footer's
   recorded entry count does not equal the number of entries the
   walker consumed.
4. **Every IFRAME (when present) reproduces the same per-entry
   shape as its preceding ENTRY.**  See "IFRAME validation"
   below.
5. **Every byte budget rolls up exactly.**  ``cst_audit`` verifies
   this — the HEADER + BODY member sizes sum to the uncompressed
   total, and the HEADER BREAKDOWN sub-groups sum back to the
   HEADER member (a ``[rollup 100.00%]`` line asserts it).  A
   non-100 % rollup or an ``UNACCOUNTED`` line is a writer bug.

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
Drop the IFRAME flag once you have a clean decode; the
production trace is byte-identical to one produced without IFRAME
generation.

mnemonic survey / audit
-----------------------

Two helpers tied to the disassembly classification step rather than
the wire format:

* ``champsim_tracer_mnemonic_survey.py`` is a static mnemonic-coverage
  analyzer.  It parses ``champsim_tracer_mnemonics.h`` to build the set
  of known instruction IDs per ISA, disassembles one or more input ELF
  binaries with Capstone, and reports any instruction IDs the
  classification tables do not cover.  Useful when adding ISA support:
  it tells you which mnemonics need rows in
  ``champsim_tracer_mnemonic_tables.cc``.

* ``champsim_tracer_mnemonic_audit.py`` audits *and regenerates* the
  classification tables.  It derives the mnemonic universe from the
  in-tree Capstone C enum headers (not from mnemonics observed in any
  run), checks each against the static classification table, and
  reports any unclassified ones.  Run after adding a new opcode or ISA
  to confirm the table covers the full Capstone surface.

Neither tool reads a ``.cst`` trace: the survey works from ELF
binaries and the Capstone tables, and the audit works from the
Capstone C enum headers and the tables.

Reusing the decoder library
---------------------------

.. index::
   single: decoder library
   single: self-describing trace

The decoder bundle (``cst_common`` / ``cst_reader`` / ``cst_format``
/ ``cst_decode``, plus optional ``cst_objdump``) is plain C++17 over
a small POSIX set (``mmap`` / ``fork`` / ``pipe``) and is meant to
be lifted into your own consumer wholesale.  The design rules a
re-user must respect:

* **Strictly self-describing — no compile-time enum dependency.**
  Every header carries twelve encoding maps (opcode, branch_type,
  reg, field_id, header_flag, insn_flag, body_tag, wp_event_flag,
  metaflags, dep_block_flag, mem_access_pattern, profile_flag).  The
  tools reverse-resolve *names* into IDs at load time and dispatch
  off those; a future writer that renumbers IDs stays decodable as
  long as its maps carry the names.  A conforming decoder requires
  only a small structural set of names plus an entry for every value
  the trace actually uses (see :doc:`/format`, Step 3.3); a trace
  missing a *required* name is malformed (load throws).  The
  in-tree writer emits the full canonical name set in every map by
  convention, not by format requirement.
* **Slot families resolve by full name, never by arithmetic.**
  There is deliberately no exposed ``SLOT_STRIDE``: per-slot
  families (``LOAD_ADDR``/``STORE_ADDR``/``LOAD_DATA``/
  ``STORE_DATA``/``DST_REG`` and the four lane-mask families) are
  looked up as ``CST_FID_<family><k>`` for each ``k`` the trace
  uses.  The decoder's internal dense slot order is unrelated to the
  wire ID; both ends resolve by name, and the decoder's dispatch
  depends on resolving the names it needs — the structural set it
  always requires plus the family/slot names for values the trace
  carries.  A trace need only name the structural set plus the
  entries for values it actually uses; the in-tree writer
  enumerates the full canonical set as a convenience, not because
  the format demands it.
* **Capstone is optional.**  Without ``-DCST_HAVE_CAPSTONE``
  ``cst_objdump`` compiles to a stub and ``--objdump`` simply
  disables — downstream re-users link cleanly without bundling
  Capstone.
* **Bring your own byte source.**  A ``Reader`` can wrap any byte
  source; consumers may bypass ``cst_file_open`` / the ustar +
  decompressor machinery entirely.  Streaming readers pull through
  a sliding buffer so a 100 GB body never has to be resident, and
  the bundled decompressor uses a separate feeder child so a
  single-threaded parent doing ``write(in)`` + ``read(out)`` cannot
  deadlock when the codec's stdin buffer fills before it produces
  output.

Internally the field-delta replay is two passes (apply every wire
record to its ``(insn, slot)`` state cell, then materialise one row
per template instruction).  State cells use a per-table generation
counter so a segment boundary invalidates every cell in O(1).  The
state-cell layout (``FIELD_STATE_SLOT_COUNT``) is a compile-time
constant shared by this decoder and the writer; adding a new field
family changes it in both.  This is a source-level coupling of the
offline tools, independent of the wire format's ``CST_MAGIC``
epoch; the trace stays self-describing through its ``field_id``
map.
