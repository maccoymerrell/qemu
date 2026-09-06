.. _upstream-coverage:

Upstream coverage gaps
======================

An instruction the tracer cannot trace because *QEMU does not execute
it* is a fact about QEMU, not a property of the tracer.  This page is
the report those facts are filed as: one row per family, each with the
measurement that found it, the fault the machine actually delivers, and
the change that would close it.  Nothing here is restated as a tracer
limitation — :doc:`limitations` is for categories the tracer is
deliberately out of, and a missing emulator feature is not one of them.

.. note::

   The numbers below are encoding counts from the x86_64 sweep of the
   arc-3 encoding population — 7,108,679 slots, of which 295,763
   produce no template chain.  111 distinct mnemonics cover all
   295,763, and one representative of each was executed on native
   hardware and under ``qemu-x86_64``.  That is exhaustive over classes
   by construction.

.. _upstream-coverage-two-classes:

Two classes, and the bit that separates them
--------------------------------------------

.. code-block:: text

   both machines refuse it                        241,539
   the HOST EXECUTES it and QEMU raises #UD        54,224

The split is not a judgement call.  Every one of these families is
gated by a CPUID feature bit, and the class a family lands in is
exactly whether the *host* advertises that bit:

.. code-block:: text

                     host   qemu-x86_64
      INVPCID          1         1        <-- advertised by BOTH, and QEMU #UDs
      RTM              1         0
      AVX512F/DQ/BW    1         0
      GFNI             1         0
      VMX              1         0
      HLE              0         0
      XOP, FMA4        0         0
      CET_SS, CET_IBT  0         0
      MOVDIRI/64B      0         0
      PTWRITE          0         0   (CPUID leaf 0x14 absent under QEMU)

Measured with a CPUID probe run on both machines
(``featbits.c``; ``qemu-x86_64`` with its default user-mode CPU model).

Read down the column and the report writes itself.  For every family
but one, ``qemu-x86_64`` advertises **0** — so ``#UD`` is the
architecturally correct answer, QEMU is self-consistent, and what is
owed upstream is the *feature*, not the fault.  ``INVPCID`` is the sole
row where QEMU advertises the bit **and** refuses the instruction, and
that makes it a different defect from every other row on this page.

.. _upstream-invpcid:

INVPCID — the wrong fault class (6,000 encodings)
--------------------------------------------------

**Observed.**  ``66 0F 38 82 /r`` at CPL 3, on a machine that
advertises the feature:

.. code-block:: text

   native host    CPUID.7.0:EBX.INVPCID = 1   fault = SIGSEGV  -> #GP(0)
   qemu-x86_64    CPUID.7.0:EBX.INVPCID = 1   fault = SIGILL   -> #UD

**Expected.**  The SDM gives ``#UD`` for INVPCID only when
``CPUID.(EAX=07H,ECX=0H):EBX.INVPCID[bit 10] = 0``.  With the bit set,
the CPL check runs first and a CPL > 0 execution takes ``#GP(0)``.  So
the two lines above disagree about the architecture, not about a
choice.

**Why QEMU advertises it.**  ``target/i386/cpu.c`` sets the bit
deliberately in user-mode builds::

   #if defined CONFIG_USER_ONLY
   #define CPUID_7_0_EBX_KERNEL_FEATURES CPUID_7_0_EBX_INVPCID
   #else
   #define CPUID_7_0_EBX_KERNEL_FEATURES 0
   #endif

added by commit ``d903259dd2`` ("target/i386: ignore CPL0-specific
features in user mode emulation"), whose reasoning is that features
reachable only through privileged operations "have no impact on any
user-mode operation", so reporting them lets ``-cpu`` name more models.
The same file's own comment two lines below still lists
``CPUID_7_0_EBX_INVPCID`` under ``/* missing: */``.

**Where the reasoning does not reach.**  The *fault* is a user-mode
observable.  A CPL 3 program that executes the instruction — a feature
probe, a fuzzer, a sandbox escape test — sees ``SIGILL`` where hardware
sends ``SIGSEGV``.  The instruction's opcode is not in
``opcodes_0F38_00toEF[]`` at all, so the decoder never reaches a CPL
check and answers with the decode-table's default.

**Fix path.**  Give ``0F 38 82`` a decode-table row carrying
``chk(cpl0) cpuid(INVPCID) p_66``.  The check machinery already
exists — ``X86_CHECK_cpl0`` is tested in ``decode_insn()`` before the
SVM intercepts and jumps to ``gp_fault`` — so the row alone moves the
user-mode answer from ``#UD`` to ``#GP(0)``.  In system-mode builds
``CPUID_7_0_EBX_KERNEL_FEATURES`` is 0, the ``cpuid(INVPCID)`` check
fails and the ``#UD`` those builds already give is unchanged; the row's
emitter is therefore unreachable at this tip and stays so until a
future change adds ``CPUID_7_0_EBX_INVPCID`` to
``TCG_7_0_EBX_FEATURES`` and implements the TLB operation.

The alternative — dropping the bit from
``CPUID_7_0_EBX_KERNEL_FEATURES`` — also makes QEMU self-consistent,
by making ``#UD`` correct.  It is not preferred here because it
reverses a deliberate upstream decision and costs the ``-cpu`` model
coverage that decision bought, where the decode row costs nothing.

.. _upstream-missing-features:

Missing features — the ``#UD`` is correct, the emulation is short
------------------------------------------------------------------

Each row below is a family whose CPUID bit ``qemu-x86_64`` reports as
0.  The ``#UD`` is the architecture's own answer for an unsupported
feature and is *not* a defect; what is owed is the implementation.
They are listed because a consumer of a trace has to know which
instructions the trace cannot contain, and because "QEMU implements no
GFNI" is a sentence that belongs in a bug report rather than in a
tracer limitation.

.. list-table::
   :header-rows: 1
   :widths: 22 12 66

   * - family
     - encodings
     - what is missing
   * - GFNI
     - 36,573
     - ``gf2p8affineqb``, ``gf2p8affineinvqb``, ``gf2p8mulb`` and their
       VEX forms.  No GF(2^8) helpers exist in ``target/i386``; the
       feature bit is not in ``TCG_7_0_ECX_FEATURES``.  Fix path: the
       three helpers plus ``0F 3A CE/CF`` and ``0F 38 CF`` decode rows.
   * - AVX-512 / EVEX + opmask
     - 3,404
     - ``kshift*`` and EVEX-encoded forms.  QEMU's x86 decoder has no
       EVEX prefix path and no opmask register file.  Fix path is the
       standing upstream AVX-512 work, not a local change.
   * - RTM
     - 192
     - ``xabort``, ``xbegin``.  ``CPUID_7_0_EBX_RTM`` is named in the
       same ``/* missing: */`` comment as INVPCID and, unlike INVPCID,
       is genuinely not advertised — so QEMU is already self-consistent
       here.  Fix path: implement the always-abort form (an RTM
       implementation that aborts every transaction is architecturally
       legal) or leave the feature unadvertised, which is the current
       state and is correct.
   * - undocumented group-F7 ``/1``
     - 855
     - ``testl`` / ``testq`` / ``testw`` through the ``/1`` alias of
       group 3, which every x86 implementation executes and no manual
       documents.  Not a feature bit at all: the decode table maps
       ``/1`` to nothing.  Fix path: point ``/1`` at the same entry as
       ``/0``, which is what silicon does.
   * - CET shadow stack
     - 28,612
     - part of the 241,539: the host does not advertise ``CET_SS``
       either, so both machines refuse.  Fix path is upstream CET work.
   * - MOVDIR
     - 11,994
     - ``movdiri`` / ``movdir64b``; neither machine advertises the bits.
   * - PTWRITE
     - 4,624
     - ``ptwrite``; CPUID leaf 0x14 is absent under QEMU entirely.
   * - FMA4 / XOP
     - 135,168
     - AMD-only encodings neither machine advertises.
   * - VMX
     - 12,000
     - nested-virtualisation opcodes; ``CPUID.1:ECX.VMX`` is 0 under
       ``qemu-x86_64``, so the ``#UD`` is correct in user mode.
   * - VIA PadLock
     - 864
     - Centaur-only; neither machine is a Centaur part.

Two families in the first class were **defects rather than gaps** and
have been fixed in this tree:

* ``0F C7 /1`` under a 66 / F3 / F2 prefix — 7,200 encodings that
  hardware executes and QEMU refused, because ``validate_sse_prefix()``
  treated a prefix the opcode has no mandatory use for as a mandatory
  one.  Fixed line-neutrally in ``3370b56c91``.
* ``VROUNDSS`` / ``VROUNDSD`` at ``VEX.L=1`` — VEX.LIG encodings the
  architecture defines, on which QEMU *asserted* and killed the
  emulator.  Fixed in ``067a5a798c``; the abort had been absorbing
  692,151 encodings of the sweep as "cause not determined".

.. _upstream-coverage-instrument:

The twenty-one that are the instrument's own
---------------------------------------------

``ret`` and ``repz ret`` — 21 encodings — are executed by both
machines and produce no chain because the instruction *leaves the
slide* the encoding sweep plants it in.  That is a property of the
measurement, and it is stated here rather than absorbed into either
class above.
