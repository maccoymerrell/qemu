"""
Adjudication rules for the gem5 execution leg.

Every entry names a MECHANISM and the set relation that mechanism can produce.
A label that only restates which way the two sets differ, or that groups rows
of more than one mechanism, is declared with ``accounts=False`` so its rows
stay UNACCOUNTED -- the taxonomy's way of refusing a label that explains
nothing.

Author: Maccoy Merrell.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..'))
from arc3_taxonomy import Rule, SUPERSET, SUBSET, ORTHOGONAL, ANY

GEM5_EXEC = {
    'VALUE-MISMATCH':
        Rule('VALUE-MISMATCH', 'tracer-defect', {SUBSET},
             note='a register or a memory byte both sides name, valued '
                  'differently: one of the two is wrong about what the '
                  'machine did, and it is not the machine'),

    # gem5's AArch64 decoder does not name the zero register as a destination
    # at all: an encoding whose Rd is 31 (`cmp` = `subs xzr, ...`) reaches the
    # ExeTracer with no integer destination, so the reference has nothing for
    # the tracer's REG_ZERO write to disagree with.  Spike does the same thing
    # on x0 (`REF-X0-DISCARD` on the riscv64 leg), for the same reason.
    'REF-DISCARDS-ZERO-DEST':
        Rule('REF-DISCARDS-ZERO-DEST', 'reference-gap', {SUPERSET},
             note='gem5 discards a zero-register destination at decode; a '
                  'tracer REG_ZERO write has no counterpart to disagree with'),

    # BYTE-FOR-BYTE THE SAME ACCESSES, SPLIT DIFFERENTLY.  Measured, not
    # assumed: the label is emitted only when the two byte sets are EQUAL and
    # the request counts differ.  gem5 cracks `ld2`/`ld3`/`ld4`, `ldp`/`stp`
    # and `ldr q` into one request per register; the tracer records QEMU's
    # own access split, which for the de-interleaving forms is one request
    # per element.  Neither is wrong about what the instruction touched, and
    # the memop-addr axis proves it by not firing.
    'SAME-BYTES-DIFFERENT-SPLIT':
        Rule('SAME-BYTES-DIFFERENT-SPLIT', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='identical byte coverage, different number of requests'),

    # QEMU lowers AArch64 store-exclusive onto a compare-exchange, which
    # really performs a read.  The tracer records what the guest RAN.  The
    # riscv64 leg found the same shape on `sc` and it carries the same
    # category there.
    'QEMU-EXCLUSIVE-CMPXCHG':
        Rule('QEMU-EXCLUSIVE-CMPXCHG', 'emulation-artefact', {SUPERSET},
             note='store-exclusive lowered onto a cmpxchg: the extra load is '
                  'an access the guest really made under QEMU'),

    # ------------------------------------------------------------------
    # THE ADDRESS-ONLY MEMOP.  Two rules, because two DIFFERENT mechanisms
    # produce a sized request on the reference side where the trace states an
    # address and no width, and one label covering both would explain
    # neither.  `MEMOP-WIDTH-UNSTATED` (needs-ruling) covered both and named
    # a SYMPTOM -- "the tracer states width 0" -- rather than a mechanism.
    # The ruling it was waiting for is recorded in docs/format.rst 5.2 and
    # summarised here: the extent of an operation that acts on a LINE is a
    # property of the cache being modelled, not of the instruction, so the
    # wire states the address the guest computed and the consumer applies its
    # own geometry.  Measured, on this build:
    #
    #   gem5   `Addr op_size = sys->cacheLineSize()` -- src/arch/arm/isa/
    #          insts/data64.isa:500 (dc cvau), :524 (dc cvac), :548 (dc
    #          civac).  That is System.cache_line_size, the SIMULATOR's
    #          configured geometry (src/sim/System.py:117, default 64;
    #          configs/common/Options.py:199 --cacheline_size).  gem5 also
    #          LINE-ALIGNS its EA with the same number (`EA &= ~(op_size-1)`).
    #   QEMU   reports the guest's architected line in CTR_EL0, and it is a
    #          per-CPU-model constant that VARIES.  Observed by running a
    #          CTR_EL0 reader under this build's qemu-aarch64:
    #          default/`max` 0x80038003 -> DminLine 32 B, cortex-a57 /
    #          -a72 / -a76 / neoverse-n1 / -a710 0x8444c004 -> 64 B,
    #          a64fx 0x86668006 -> 256 B.
    #
    # So the number is not one number.  Adopting gem5's 64 would have written
    # a gem5 config parameter onto the wire while the machine actually under
    # measurement told its own guest 32.
    'MAINT-EXTENT-IS-CACHE-GEOMETRY':
        Rule('MAINT-EXTENT-IS-CACHE-GEOMETRY', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='a cache-maintenance-by-address operation acts on a LINE; '
                  'gem5 spells that as a sized request over its own '
                  'System::cacheLineSize() and the trace spells it as an '
                  'address-only memop plus the opcode, because the extent '
                  'belongs to the modelled cache and not to the instruction'),

    # The prefetch half is a DIFFERENT mechanism and must not share the label
    # above: gem5's number here is not its cache geometry at all.  It is a
    # decoder constant -- `LoadImm64("prfm", "PRFM64_IMM", size=8,
    # flavor="mprefetch")`, src/arch/arm/isa/insts/ldr64.isa:428-430 -- and 8
    # is neither the line size gem5 models (64) nor anything the guest can
    # observe.  The architecture leaves a prefetch's access size
    # IMPLEMENTATION DEFINED and QEMU's TCG emits no memop for PRFM at all,
    # so there is no width to record and the trace records none.
    'PREFETCH-SIZE-IS-REF-CHOICE':
        Rule('PREFETCH-SIZE-IS-REF-CHOICE', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note="a prefetch's access size is IMPLEMENTATION DEFINED; gem5 "
                  'hardcodes 8 in its decoder and QEMU emits no access, so '
                  'the trace states the address and no width'),

    # gem5's AArch64 DC ops are built with an empty write-back
    # (`"op_wb" : ";"`, src/arch/arm/isa/insts/data64.isa:477 for DC ZVA and
    # :505, :529, :553 for the clean/invalidate forms) and carry no
    # destination operand, so the instruction reaches the ExeTracer naming no
    # register at all.  The trace names REG_SYSCACHE, which is what lets a
    # consumer order the operation against the accesses that depend on it --
    # the same reason REG_ZERO is named where gem5 discards it.
    #
    # Worded for the DC class and not for "maintenance": DC ZVA is a cache
    # operation the trace marks the same way, and gem5's own comment says it
    # is deliberately NOT classified as cache maintenance.  A rule whose text
    # is true of only some of the rows it covers is this project's named
    # dominant defect class.
    'REF-NO-CACHE-MAINT-DEST':
        Rule('REF-NO-CACHE-MAINT-DEST', 'reference-gap', {SUPERSET},
             note='gem5 gives a data- or instruction-cache operation no '
                  'destination register; the trace names REG_SYSCACHE'),

    # IC IVAU is the one member of the class gem5 decodes as an ordinary
    # system-register write -- its own disassembly reads `msr ic_ivau_xt,
    # x21` -- so it writes a misc register named after the operation where
    # the trace names REG_SYSCACHE.  One fact, two spellings; distinct from
    # REF-NO-CACHE-MAINT-DEST, where the reference names nothing at all.
    'CACHE-MAINT-DEST-SPELLING':
        Rule('CACHE-MAINT-DEST-SPELLING', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='gem5 spells an instruction-cache maintenance destination '
                  'as its own operation-named misc register; the trace '
                  'names REG_SYSCACHE'),

    # DC ZVA is NOT cache maintenance -- it writes zeros, and both tools
    # perform the stores.  They disagree only on how big the block is, and
    # the block size is architected per machine in DCZID_EL0, which each
    # simulator answers for itself:
    #   gem5   `uint64_t op_size = 1ULL << (Dczid + 2)`, src/arch/arm/isa/
    #          insts/data64.isa:468 -- its own DCZID, 64 B on this build.
    #   QEMU   observed by running a DCZID_EL0 reader under this build's
    #          qemu-aarch64: default/`max` reports 7 -> 512 B, cortex-a57
    #          reports 4 -> 64 B, a64fx reports 6 -> 256 B.
    # Each side zeroes the block ITS machine defines, and each is right
    # about its own.  Both also align the base to their own block, so the
    # smaller run sits inside the larger one -- which is what the selector
    # requires, so a trace that zeroed somewhere ELSE does not earn this.
    'DCZVA-BLOCK-IS-MACHINE-SIZE':
        Rule('DCZVA-BLOCK-IS-MACHINE-SIZE', 'emulation-artefact', ANY,
             note='the zero-block size is architected per machine in '
                  'DCZID_EL0; the two simulators answer it differently and '
                  'each zeroes the block its own machine defines'),

    # gem5 does not model FPSCR as one register: it splits it into
    # `fpscr_exc`, `fpscr_qc` and the rest, and writes `fpscr_exc` on every FP
    # operation whether or not this execution changed a flag.  The tracer
    # names one REG_FCSR.  Neither spelling is wrong; they are not the same
    # register.
    'FPSR-GRANULARITY':
        Rule('FPSR-GRANULARITY', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='gem5 splits FPSCR into sub-field registers and writes the '
                  'exception sub-field unconditionally'),

    # gem5 splits AArch64's NZCV into nz / c / v.  Same fact, three names.
    'FLAGS-GRANULARITY':
        Rule('FLAGS-GRANULARITY', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='gem5 splits NZCV into three condition-code registers'),

    # gem5's NEON load/store micro-ops write vector registers in PAIRS, so a
    # form with an odd register count names one register the instruction does
    # not write.  `ld1 {v5.16b}` reports v5 AND v6; `ld1 {v8,v9,v10}` reports
    # v8..v11; the two- and four-register forms agree exactly.  The
    # architecture is unambiguous here and the tracer matches it.
    'REF-NEON-PAIRWISE-DEST':
        Rule('REF-NEON-PAIRWISE-DEST', 'reference-defect', {SUBSET},
             note='gem5 names vector destinations in pairs; the odd-count '
                  'LD1/LD1R/LD3 forms gain one register that is not written'),

    # A value the reference read out of an implementation-defined
    # identification register (CTR_EL0, DCZID_EL0) or a free-running counter
    # (CNTVCT_EL0).  Two different modelled CPUs, two right answers.
    'IMPLDEF-MACHINE-VALUE':
        Rule('IMPLDEF-MACHINE-VALUE', 'emulation-artefact', ANY,
             note='sourced from an implementation-defined id register or a '
                  'free-running counter; the two simulators model different '
                  'machines and both are right about their own'),

    # gem5's MIPS accumulator (HI/LO) writes never reach the ExeTracer:
    # `mult`, `multu`, `div`, `divu`, `madd`, `msub`, `mthi`, `mtlo` and the
    # HI/LO half of `mul` all report NO destination register.  The
    # architecture writes them and the tracer names them, so this is a hole in
    # the reference, not surplus in the trace.
    'REF-NO-ACC-WRITE':
        Rule('REF-NO-ACC-WRITE', 'reference-gap', {SUPERSET},
             note='gem5 MIPS does not publish HI/LO writes to its own '
                  'instruction trace'),

    # A DESTINATION REGISTER ON AN INSTRUCTION THAT HAS NONE.  Every mipsel
    # conditional branch -- bne, beq, bgez, bltz, blez, bgtz and the `b`
    # macro -- publishes a write to REG_GPR1 ($at) with value 0.  MIPS
    # conditional branches write no register, gem5 names no destination for
    # them, and an invented write is a defect even though the set relation
    # scores TRACER-SUPERSET: "we carry more" is only a defence when the
    # extra is true.
    'TRC-INVENTED-BRANCH-DEST':
        Rule('TRC-INVENTED-BRANCH-DEST', 'tracer-defect', {SUPERSET},
             note='mipsel conditional branches publish a REG_GPR1 write the '
                  'instruction does not perform'),

    # The reference executes an address-based hint or maintenance operation
    # as a no-op and issues NO request, so it has nothing for the trace's
    # address-only memop to disagree with.  Both measurements this rule
    # covers, each named, because a justification that is true of only one of
    # them is the defect class this project keeps catching:
    #   mipsel  gem5 implements neither `pref`/`prefe` ("Prefetching not
    #           implemented for MIPS") nor `synci` ("instruction 'synci'
    #           unimplemented").  This settles the half of W5 the static
    #           binutils axis could not see: the runtime record for those
    #           three carries a real address.
    #   aarch64 `IC IVAU` decodes to a plain `msr ic_ivau_xt, Xt` and issues
    #           no memory request at all, while QEMU (linux-user) really does
    #           act on the line -- ic_ivau_write invalidates the translation
    #           range CTR_EL0.IminLine wide, target/arm/helper.c:5199-5216.
    'HINT-MEMOP-REF-SILENT':
        Rule('HINT-MEMOP-REF-SILENT', 'reference-gap', {SUPERSET},
             note='the reference executes an address-based hint or cache '
                  'maintenance operation as a no-op and issues no request'),

    # gem5 keeps the MIPS FP condition-code bit inside FCSR and reports an
    # FCSR write; the tracer gives the condition code an id of its own.  Same
    # bit, two spellings.
    'FPCC-GRANULARITY':
        Rule('FPCC-GRANULARITY', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='the FP condition code: inside FCSR for gem5, a separate '
                  'GenericRegId for the tracer'),
}


def gem5_exec_rule(label):
    return GEM5_EXEC.get(label) if label else None
