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
  can be cross-checked against ``objdump`` output.  ``--format=raw``
  swaps the disassembly for a byte-offset-annotated pseudo-wire dump of
  the raw header and body records, for debugging the format itself.

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
   $ build/contrib/plugins/cst_decode --format=raw trace.cst > trace.wire.txt

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
   ; command=qemu-x86_64 -seed 42 -B 0x400000 -plugin libchampsim_tracer.so,outfile=run,wp=1,memdata=1,regdata=1
   ; flags=MEM_DATA REG_DATA
   ; start_insn=0 warmup_insns=0 total_target_insns=0
   ; templates=52

   ; ----- BB 3 entry pc=0x40100e insns=1 seq=1 tid=0 asid=0 (thread_switch) branch=taken target=0x401010 -----
   0x00000040100e: eb 00                    jmp     %ip, $0x401010 -> %ip[0x401010/w8]  # 0x401010 <blk_0>
   ; ----- BB 5 entry pc=0x401010 insns=9 seq=2 tid=0 asid=0 branch=taken target=0x401036 -----
   ; profile: exec_cp=1 exec_wp=0
   ; target[0]: pc=0x401036 taken_cp=1 nottaken_cp=0 taken_wp=0 nottaken_wp=0
   0x000000401010 <blk_0>: 4c 8d 3d e9 0f 00 00     lea     %ip -> %gp13[0x402000/w8]
   0x000000401017 <blk_0>: 4d 8b 47 60              mov     ld[%gp13](0x402060) -> %gp6[0x1360/w8]  ld=0x1360/w8  prof: memops_cp=1 pat_cp=CST_PAT_REGULAR cp=[0x402060-0x402060]
   0x00000040101f <blk_0>: 4d 31 c8                 xor     %gp7, %gp6 -> %gp6[0x6c92/w8], %flags[0x202/w4], %mflags[-]
   0x000000401029 <blk_0>: 4d 89 47 70              mov     %gp6 -> st[%gp13](0x402070)  st=0xc23c/w8
   ...

Per-instruction line columns:

* PC, 12 hex digits zero-padded.
* Optional ``<symbol>`` annotation when the captured template named
  the TB's owning symbol.  It names the function the instruction is
  in; the absolute PC beside it is the location, and there is no
  ``+offset`` — a template carries the symbol's NAME but not its
  base address, because the plugin API QEMU exposes
  (``qemu_plugin_insn_symbol``) returns only the name.  Printing an
  offset here would have to measure from the basic block rather than
  from the symbol, which is not what ``<sym+off>`` means anywhere
  else.
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
  snapshot (when ``regdata=1`` was set during capture).  A
  ``/w<n>`` suffix inside the brackets gives the write's byte width
  (``%dst[0x5/w4]`` is a 4-byte write), for value-prediction
  consumers; the width is the ``CST_FID_DST_REG_WIDTH`` field.
* ``%mflags[<bits>]`` — synthetic canonical-flags register
  rendered as a bit-string of set flags drawn from
  ``Z`` / ``N`` / ``C`` / ``V`` / ``P``, in that order, or ``-``
  when no flag is set.  Appears alongside ``%flags`` on ISAs with
  an integer flags register (x86, AArch64); spares consumers
  from per-ISA bit-shuffle math.  RISC-V and MIPS templates do
  not carry this slot.
* ``ld[<base>](<addr>)`` / ``st[<base>](<addr>)`` in the operand
  list — a memory operation's base register and effective address
  (``ld(<addr>)`` / ``st(<addr>)`` when no base register resolves,
  e.g. an absolute address).  A load whose value reaches no sink in
  the template's dependency masks has no place in the operand list,
  and renders in the same form *after* it instead — ``push m64``
  routes its store data straight off the address register, so its
  load appears as a trailing ``ld[%gp8](0x…)``.  Either way every
  memop the trace recorded shows its address exactly once.
  With ``memdata=1`` the loaded / stored
  value rides a trailing ``ld=<value>/w<n>`` / ``st=<value>/w<n>``
  token, where ``/w<n>`` is the access byte width — the
  ``CST_FID_LOAD_SIZE`` / ``CST_FID_STORE_SIZE`` field — for
  value-prediction consumers.  With ``memdata=0`` only the address
  operand appears and no ``ld=`` / ``st=`` token, so the absence of
  the value token unambiguously means ``memdata`` was not captured.
* ``pa=0x<paddr>`` — the reconstructed physical address of the memop,
  present only in ``physaddr=1`` system-mode traces.  It is the
  recorded physical page base (``CST_FID_LOAD_PPAGE`` /
  ``CST_FID_STORE_PPAGE``) ORed with the virtual in-page offset.
  Absent for a memop with no observed translation and from every
  user-mode or non-``physaddr`` trace.
* ``# 0x<target> <symbol>`` trailing comment — the branch's
  landing PC, decoded from the per-entry ``CST_FID_BRANCH_TAKEN`` /
  ``CST_FID_BRANCH_TARGET`` singletons (the encoded target = branch PC
  + signed displacement), with the matching symbol name when known.
  Because it is the encoded architectural successor, it is correct
  exactly where an immediate-derived guess is not — ARM ``tbz`` /
  ``tbnz`` (whose immediate is a bit index, not the label) and any
  branch diverted by a fault or interrupt.  Only for a trace predating
  the branch FIDs does the decoder fall back to the immediate-based
  template target.

Basic-block boundaries are marked by a single
``; ----- BB <template_id> entry pc=<pc> insns=<n> seq=<seq>
tid=<n> asid=<n>[ (thread_switch)][ fault_depth=<n>][ branch=taken|not-taken
target=0x<pc>] -----`` separator line (note the ``;`` prefix so it
groups with the header comments).  The ``asid`` field is the entry's
address-space id; ``(thread_switch)`` marks an entry that changed
thread; ``fault_depth=<n>`` appears inside a synchronous fault handler;
and ``branch=…/target=…`` carries the terminal branch's direction and
landing PC, decoded straight from the branch singletons with no
successor look-ahead.  Wrong-path entries are attached to their parent
CP entry's WP chain and rendered with the same per-instruction format
under a separate
``; ..... wp[k] BB <id> n_insns=<n> [status=...] -----``
separator (the ``status=FAULT@insn<n>`` suffix appears when the
WP simulator marked a synthetic-data fault at that index of the
chain entry; the fault does not end the chain, and the marked
instruction may be the block's terminator).

A system-mode trace interleaves two out-of-band records with the
entries in stream order.  A block-device request (``devio=1``) prints
``; DEVIO START req=<id> read|write|flush bytes=<n> block=<lba>
(thread=<t> asid=<a> attr=exact|pos)`` where it is issued and
``; DEVIO STOP req=<id> (thread=<t> asid=<a>)`` where its completion
lands — ``attr=exact`` is a doorbell-correlated owner, ``attr=pos``
the stream-position fallback, and the STOP inherits its START's owner.
An address-space rebase (``BODY_TAG_ASID_SWITCH``) is not rendered as
its own disasm line; it takes effect in the ``asid=`` field of the
next BB separator, and ``--format=raw`` shows the raw record.

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

``--format=raw``
   Pseudo-wire structural dump — a debugging view that walks the raw
   header and body bytes and prints every field, record, and section
   in decode order.  Each line carries the absolute byte offset within
   its member (``@xxxxxxxx``), a hex column showing the raw bytes that
   line consumed (so the output reads alongside an ``xxd`` of the same
   member), and the :doc:`format` recipe step that produced it (e.g.
   ``[Step 6.7]``), so a divergence between a producer and a
   third-party reader can be pinned to the exact byte.  The hex column
   shows up to ten bytes (longer fields end in ``+``); a field that
   straddles a decompressor-buffer refill shows ``<refill>`` instead,
   with its offset and decoded value still intact.
   Unlike ``disasm`` / ``legacy`` it does **not** reconstruct
   architectural state: field-delta records show the raw
   ``ipos_delta`` / ``fid`` / signed-delta wire values (with the
   numeric ids resolved through the trace's own encoding maps), not the
   replayed absolute field value.  Honours ``--max N`` to stop after
   ``N`` body entries; ``--objdump`` / ``--show-deps`` / ``--show-lanes``
   do not apply.

``--templates-only``
   Skip the body stream and emit the static template dictionary,
   one block per true basic block: a ``BB<id> <pc> <symbol>``
   header, the BB-level profile / target lines, then one line per
   template instruction (PC-ordered) with its inline ``prof:`` tag.
   No per-execution dynamic values — just the captured
   architectural shape plus the run-aggregated profile.  The
   analogue of ``objdump -d`` over the binary, restricted to PCs
   the guest actually executed.

   ``start_pc`` is not a unique key once self-modifying code has
   minted a revision (see :doc:`format`, *Self-modifying code*):
   a rewritten block re-executes as a second template at the same
   ``start_pc``, and both revisions are listed, in ``template_id``
   order, at their own ``BB<id>`` entries above.  Sibling revisions
   need not agree in instruction count or boundaries — a guest that
   re-cuts a block into different instructions mints a revision of
   the new shape — so each ``BB<id>`` entry is read on its own
   terms.  When any ``pc``
   carries more than one template, a trailing ``REVISIONS`` section
   lists each such ``pc`` and the ordered ``template_id`` list of
   its revisions — the sequence a body reference resolves against
   as it walks the trace — so the timeline is visible without
   scanning the whole dictionary for shared ``start_pc`` values:

   .. code-block:: text

      REVISIONS
      ---------
      0x401176: 2 revisions: BB4099 BB4119

   A trace with no self-modified code omits the section entirely.

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

Two summary lines lead the report, ahead of the byte-budget table:
a ``profile:`` line totalling the run-aggregated profile across every
template (``exec_cp`` / ``exec_wp`` execution counts, the memop- and
address-carrying instruction counts, and the four-way access-pattern
histogram ``pat[none/reg/irr/rand]`` — see :doc:`concepts`,
*Run-aggregated profile*), and, only when the trace holds
self-modified code, an ``smc:`` line tallying revision templates
(``start_pc`` values with more than one ``template_id`` — see
:doc:`format`, *Self-modifying code*) and the deepest revision chain
found. A trace with no SMC omits the ``smc:`` line entirely.

1. Run ``cst_audit`` on a baseline trace.
2. Toggle a writer flag (``wp_memdata=0``, ``wp_regdata=0``,
   ``memdata=0``).
3. Re-run.  A flag that pays off shows up as a line item shrinking
   by an order of magnitude.

Sample output (abridged):

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
     profile: exec_cp=27528 exec_wp=0  mem-insns=4920 addr-insns=1699  pat[none/reg/irr/rand]=7728/4839/56/25
   === ON DISK ===
     container (.cst)                          48.00 KiB

   === MEMBER SIZES (uncompressed) ===
     TOTAL uncompressed                       45.86 KiB  100.00%
     HEADER member                            35.41 KiB   77.22%  [   52 tmpl, avg  697.3 B]
     BODY member (records)                    10.45 KiB   22.78%

   === HEADER BREAKDOWN (35.41 KiB) ===
     preamble + encoding maps                 23.74 KiB   67.05%
     section framing (counts+lengths)             103 B    0.28%
     BB info (id/pc/n/ft/targets/sym)           1.10 KiB    3.11%  [   52 tmpl, avg  21.7 B]
     instruction descriptors                   6.77 KiB   19.11%  [   52 tmpl, avg 133.2 B]
     dependency sub-blocks                      1.01 KiB    2.85%  [   52 tmpl, avg  19.9 B]
     template profile block                    2.69 KiB    7.60%  [   52 tmpl, avg  53.0 B]
       sum                                    35.41 KiB  100.00%  [rollup 100.00%]

   === BODY BREAKDOWN (10.45 KiB) ===
     CP entry framing                              70 B    0.65%  [   35 entry, avg   2.0 B]
     CP field-delta section                     4.18 KiB   40.00%  [   35 entry, avg 122.3 B]
     WP chain envelope (incl. inner)            5.50 KiB   52.68%  [   35 entry, avg 161.0 B]
     WP events                                     82 B    0.77%  [   35 entry, avg   2.3 B]
     ...
     IFRAME records (validation redundancy)         0 B    0.00%
     REGFILE records (per-thread initial state)   609 B    5.69%  [    1 regfile]

The **HEADER BREAKDOWN** attributes every header byte to a
template-block group, so the cost of each piece of static metadata
is visible: ``BB info`` (the per-BB header — id, start PC, insn
count, ``fall_through``, the terminal-branch ``n_targets`` / target
list, symbol), ``instruction descriptors``, optional ``dependency
sub-blocks``, and the run-aggregated ``template profile block``.
The **BODY BREAKDOWN** likewise covers every body record kind: CP
and WP entry framing and field-delta sections, WP events,
``thread-switch records`` (one per ``BODY_TAG_THREAD_SWITCH``),
``asid-switch records`` (one per ``BODY_TAG_ASID_SWITCH``), the
``DEVIO START`` / ``DEVIO STOP`` disk-request lines (system mode with
``devio=1``), ``REGFILE records`` (one ``BODY_TAG_REGFILE`` per
thread, carrying that thread's initial regfile snapshot), the
``IFRAME records`` line, and the body terminator.  The field-delta
section is itself split per field-ID family, including a ``physical
pages`` bucket (the ``physaddr=1`` ``CST_FID_*_PPAGE`` records) and a
``branch outcome`` bucket (the always-present ``CST_FID_BRANCH_TAKEN``
/ ``CST_FID_BRANCH_TARGET`` singletons).  The ``IFRAME records`` line appears
only on traces produced with ``iframe_rate>0``; those bytes are
pure validation overhead and disappear when the feature is off.

When the trace carries register data (``regdata=1``), the
**dest registers** line of the field-delta breakdown is typically the
single largest body cost.  A **REGISTER-DATA BREAKDOWN** section then
splits that one bucket down to the individual architectural register:
each field-delta record charges its bytes to the register the
record's template binds to that destination slot, resolved through
the header's register-name map.  Rows are sorted by total bytes, each
showing the correct-path / wrong-path split and record count, and the
section reconciles — the per-register bytes sum back to the
``dest registers`` bucket (a ``rollup ... of dest-register bucket``
line asserts it; any residue that could not be tied to a register
lands in an ``(unresolved)`` row).  This is the tool to reach for when
``regdata`` blows up a trace and you need to know *which* register is
responsible — a single hot accumulator or the flags register often
dominates, and the CP/WP split shows whether the cost is correct-path
state or wrong-path speculation.

An **ATTRIBUTION LINT** verdict always closes the report:
``impossible attributions: <n> memop (<m> distinct insns), <n> regdata
(<m> distinct insns), <n> dangling template refs (<m> distinct ids)``.
This is a structural sanity check, not a byte accounting: it flags a
body observation landing on an instruction that statically cannot
produce it — a memop value on an insn with zero static load/store
slots, a destination-register value past the template's static dst
count, or a CP/WP entry naming a ``template_id`` the templates section
never defines — the signature of attribution corruption (records
leaking into the wrong entry's drain) rather than a decode-quality
nuance. It is always printed and, unlike every other line in the
report, a nonzero count is fatal: ``cst_audit`` exits 1 instead of 0.
A clean trace always reads ``impossible attributions: 0 memop (0
distinct insns), 0 regdata (0 distinct insns), 0 dangling template
refs (0 distinct ids)``.

Conservation vs. completeness
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Everything above this point — the byte-budget breakdown, the
``[rollup 100.00%]`` assertions, the register-data breakdown, even the
attribution lint — is a **conservation** check: it partitions and
cross-foots bytes and records that ARE on the wire.  A record the
writer never emitted contributes to neither side of a partition, so
its absence reconciles exactly and silently.  That blind spot is not
hypothetical: it is exactly how the D4 bug — a deferred trace-window
close that flushed a segment's final body entry before its
instructions had run, so the entry carried no memops and no register
deltas at all — passed every one of the checks above in every affected
trace, with the header breakdown rolling up to 100.00% and the
attribution lint reading all-zero throughout.

The two sections below are **completeness** checks instead: they look
for what SHOULD be on the wire, by the trace's own internal evidence,
and is not.  Both are off by default in neither direction — they run
automatically and gate ``cst_audit``'s exit code exactly like the
attribution lint — but both are statistical or sidecar-dependent
rather than absolute, precisely because "an instruction produced no
observation this execution" is legitimate on its own (predication, a
zero-count REP, a suppressed fault, ordinary wrong-path wandering) and
only becomes suspicious in the pattern these checks look for.

.. _bimodality-cc:

MEMOP BIMODALITY (Oracle 2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. index::
   single: memop bimodality
   single: MemopBimodalityLint

For each memop-capable template (at least one instruction with a
nonzero static load or store count), ``cst_audit`` tallies how many of
its correct-path executions realised at least one memop versus how
many realised none — reconstructed from the persistent
``CST_FID_N_LOADS`` / ``CST_FID_N_STORES`` cells (format.rst §5.2),
not from raw record presence, because those fields are delta-encoded
against their own prior observation like every other field: a steady
repeated count re-emits nothing after its first sighting, so record
presence alone cannot tell "unchanged" from "never happened".  A
template that is overwhelmingly nonzero with only a SMALL minority of
zero-memop executions is the D4 signature: one or a few executions
silently lost their memops while the template's ordinary behaviour is
unambiguous.  A template that is legitimately bimodal AT SCALE (heavy
predication, a REP loop empty as often as not) has a zero-rate the
default threshold does not consider an outlier, so it is not flagged.

A fault-truncated execution is excluded from the population outright.
An entry carrying fault anchors (``fault_at``, format.rst §6.7) stopped
part-way through its template — in the limit at instruction 0, before
any memop-capable instruction retired — so it never had the opportunity
to realise the template's memops, and the wire records precisely that.
The canonical case is a kernel copy loop taking a page fault on its
first store: one truncated execution against fifty complete ones is the
D4 *shape* without being a D4 *loss*.  Excluding them costs the oracle
no strictness, because the loss it exists to catch is a silent one and a
silently dropped memop section carries no anchor.  The report prints the
excluded count so the exclusion is never invisible.

The lint is implemented in ``tools/cst_lint.h``
(``cst::MemopBimodalityLint``), correct-path only — wrong-path
wandering carries no dataflow contract, the same scoping the
attribution lint's MEM/REG rules use.  Two tunables tighten or loosen
the statistical band for a workload whose legitimate zero-rate
genuinely warrants it:

.. code-block:: console

   $ build/contrib/plugins/cst_audit --bimodal-min-execs=20 \
         --bimodal-max-outlier-rate=0.05 trace.cst
   $ build/contrib/plugins/cst_audit --bimodal-off trace.cst   # skip it

``--bimodal-min-execs=N`` (default 8) is the minimum CP-execution count
before a template's zero-rate is judged at all — too few samples make
"1 zero out of 3" indistinguishable from noise.
``--bimodal-max-outlier-rate=F`` (default 0.10) is the fraction of
zero-memop executions, at or below which they count as "a small
minority of outliers" rather than the template's own normal behaviour.
The report section always prints, clean or not:

.. code-block:: console

   === MEMOP BIMODALITY (Oracle 2; min_execs=8, max_outlier_rate=0.10) ===
     clean: 0 templates with a nonzero-majority / zero-outlier memop split

A nonzero finding prints one line per flagged template (id, execution
count, outlier count, rate) and fails the audit (exit 1), the same
contract as the attribution lint.

.. _completeness-cc:

COMPLETENESS (Oracle 1)
~~~~~~~~~~~~~~~~~~~~~~~

.. index::
   single: completeness check
   single: reg-snap accounting
   single: stats.log

The plugin already computes a completeness invariant at trace-generation
time that never reaches the wire at all: ``CP reg-snap slice dropped``
and ``CP reg-snap leak trimmed`` (:doc:`reference`, Stats), printed in
the plugin's own per-segment and cumulative summaries.  A positional
reg-snap shortfall the seal walk cannot recover drops that entry's
whole register-data section rather than mis-slicing it onto the wrong
instruction (counted as *dropped*); a leaked prefix the walk CAN
recover by trimming is counted separately as *trimmed*.  On a
conformant run these two counters are equal — every genuine shortfall
is either a recoverable leak or an unrecoverable drop the counter
itself accounts for.  The invariant is ``dropped == trimmed``, not
"both zero": a busy fault-storm trace can legitimately trim many
leaked prefixes while dropping none of them, so requiring zero would
false-positive on exactly the traces most likely to exercise the
recovery path.

Because the two counters live only in the plugin's own
``<outfile>.stats.log`` sidecar (:doc:`quickstart`, *Output files and
stderr*) — never on the wire — a pure trace-file reader cannot recover
them after the fact.  ``cst_audit`` auto-detects the sidecar beside the
trace (stripping a trailing ``.cst`` from the trace path and appending
``.stats.log`` — the common ``outfile=run`` case, where it lands at
``run.stats.log``; simpoint mode's position-suffixed segment files do
not map back this way and need ``--stats-log`` explicitly) or accepts
an explicit path:

.. code-block:: console

   $ build/contrib/plugins/cst_audit --stats-log=run.stats.log run.cst
   === COMPLETENESS (Oracle 1; run.stats.log) ===
     CP reg-snap slice dropped               0
     CP reg-snap leak trimmed                0
     invariant dropped == trimmed: OK

When no sidecar is found (auto-detected path missing) the section is
silently omitted — this is the offline half of a check the validator
also runs at trace-generation time as a registered, gating feature
(``features.reg_snap_accounting``, :doc:`validator`); passing an
explicit ``--stats-log`` that turns out unreadable or missing either
counter IS an error (``cst_audit`` exits 1), so a consumer who
deliberately asks for the check gets a hard answer, not a silent skip.

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
6. **Every template id the body references is defined.**  Each CP
   ``ENTRY`` and each WP chain block names a template id, and the
   trace's own templates section is the id's only definition — a
   reference with no definition means the writer emitted entries
   whose templates never serialized, and the trace cannot be
   replayed.  Both tools count these as *dangling template refs*
   in the attribution-lint summary: ``cst_audit`` fails (exit 1)
   on any, and ``cst_decode --strict`` escalates its trailing
   lint summary to exit 1.  WP id 0 is exempt (the writer's
   "no template" sentinel; real ids start at 1).
7. **Every branch's recorded outcome agrees with where its context
   actually went.**  ``cst_decode --verify-branch[=N]`` cross-checks
   each branch-terminated CP entry's ``CST_FID_BRANCH_TAKEN`` /
   ``CST_FID_BRANCH_TARGET`` against the *architectural continuation*
   — the entry where its ``(thread, asid)`` context resumes the
   encoded target, at that entry's ``start_pc`` or at one of a
   fault-merged entry's anchors — rather than against the next entry
   in stream order; a pair the next entry does not resolve is deferred
   only on a positive diversion signal (a ``fault_depth`` step, the
   successor's fault anchors, a thread switch, a privilege-domain gap,
   or both endpoints inside a kernel excursion) and must then be
   resumed or corroborated by a later entry of the same context.  WP
   chain blocks are checked in-chain against the next block's
   ``start_pc``.  Every diversion is tallied by signal
   (resumed / corroborated / never-resumed); an unresumed mismatch
   with no diversion signal exits 1.  ``=N`` caps the number of body
   entries walked.  See :doc:`format` §5.6 for the full diversion
   taxonomy and the wire contract this check verifies.

The recommended validation workflow:

.. code-block:: console

   $ build/contrib/plugins/cst_audit trace.cst
   # HEADER BREAKDOWN must end in '[rollup 100.00%]'

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
