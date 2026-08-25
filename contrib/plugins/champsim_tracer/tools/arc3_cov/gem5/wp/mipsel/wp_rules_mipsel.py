"""
Adjudication rules for the gem5 WRONG-PATH execution leg.

Every entry names a MECHANISM and the set relations that mechanism can
produce.  A label that only restates which way the two sets differ, or that
groups rows of more than one mechanism, is declared with ``accounts=False`` so
its rows stay UNACCOUNTED -- the taxonomy's way of refusing a label that
explains nothing.

THE POINT OF THE TABLE, on this leg specifically.  A wrong-path row whose set
relation is TRACER-SUPERSET is COVERED only when a rule here says WHY the
reference cannot state the fact.  Without that, "we carry more" is not a
defence: gem5 already caught one mipsel row this arc where the tracer carried
a REG_GPR1 destination on every conditional branch that the instruction does
not write (fixed at 95a0d89e92), and it scored TRACER-SUPERSET the whole time.
An unexplained superset is a defect wearing the right-looking direction.

Author: Maccoy Merrell.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', '..', '..'))
from arc3_taxonomy import Rule, SUPERSET, SUBSET, ORTHOGONAL, ANY   # noqa

MIPSEL_WP = {
    # ---------------------------------------------------------- reference gaps
    # gem5's MIPS `jr`/`jr.hb` is implemented as
    #     Config1Reg config1 = Config1;
    #     if (config1.ca == 0) { NNPC = Rs; } else panic("MIPS16e ...");
    # (src/arch/mips/isa/decoder.isa:136).  Reading an implementation
    # CONFIGURATION word to decide whether MIPS16e exists is a property of
    # gem5's model, not of the instruction: `jr` reads rs and nothing else, and
    # no renaming regfile would have to respect an edge to Config1 (R7).  The
    # reference names a source the architecture does not have.
    'REF-JR-READS-CONFIG1':
        Rule('REF-JR-READS-CONFIG1', 'reference-defect', {SUBSET, ORTHOGONAL},
             note='gem5 MIPS jr/jalr.hb reads misc Config1 to test the MIPS16e '
                  'capability bit; the architecture does not'),

    # gem5 maps a MIPS operand naming $zero to the `invalid` register class and
    # the ExeTracer prints `invalid:0`, so the reference has no name for the
    # zero register at all.  R7.3 rules that REG_ZERO stays on the wire: the
    # tracer is right and the reference simply cannot say it.
    'REF-ZERO-OPERAND-AS-INVALID':
        Rule('REF-ZERO-OPERAND-AS-INVALID', 'reference-gap', {SUPERSET},
             note='gem5 renders a $zero operand as the invalid register class; '
                  'REG_ZERO has no counterpart on the reference side'),

    # gem5's MIPS accumulator writes never reach the ExeTracer: mult, multu,
    # div, divu, madd, msub, mthi, mtlo and the HI/LO half of mul report no
    # destination.  The architecture writes them and the tracer names them.
    'REF-NO-ACC-WRITE':
        Rule('REF-NO-ACC-WRITE', 'reference-gap', {SUPERSET},
             note='gem5 MIPS does not publish HI/LO writes to its own '
                  'instruction trace'),

    # gem5's MIPS implements neither pref/prefe ("Prefetching not implemented
    # for MIPS") nor synci ("instruction 'synci' unimplemented"), so it issues
    # no request and has nothing for the tracer's runtime memop to disagree
    # with.
    'HINT-MEMOP-REF-SILENT':
        Rule('HINT-MEMOP-REF-SILENT', 'reference-gap', {SUPERSET},
             note='gem5 MIPS executes pref/prefe/synci as no-ops and issues no '
                  'memory request'),

    # gem5 keeps the MIPS FP condition code inside FCSR and reports an FCSR
    # write; the tracer gives the condition code an id of its own.  Same bit,
    # two spellings.
    'FPCC-GRANULARITY':
        Rule('FPCC-GRANULARITY', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='the FP condition code: inside FCSR for gem5, a separate '
                  'GenericRegId for the tracer'),

    # gem5 MIPS keeps a MIPS32 register value ZERO-EXTENDED in its 64-bit
    # RegVal (operands.isa:52-54 give Rs/Rt the type `uw` = uint32_t, and
    # decoder.isa:2476 `lw({{ Rt = Mem_sw; }})` therefore lands
    # 0xffc9c1a0 in the file as 0x00000000ffc9c1a0), while the SIGNED
    # accumulator forms read that register through the 64-bit signed view --
    #     decoder.isa:186  mult({{ val = Rs_sd * Rt_sd; }})
    #     decoder.isa:191  div ({{ HI0 = Rs_sd % Rt_sd; LO0 = Rs_sd / Rt_sd; }})
    # so a negative 32-bit operand is multiplied and divided as a large
    # POSITIVE 64-bit one.  MEASURED, not asserted: the harness recomputes the
    # MIPS32 answer from the reference's OWN source values and reports which
    # side it matches -- on t2=0xffc9c1a0, t3=0x370cea6f the architectural
    # signed HI is 0xfff455dc (the tracer's), gem5's 0x3701404b is the
    # UNSIGNED product's high word, and `mfhi` then carries the wrong value
    # into a general register.  LO is unaffected, which is why this hides
    # until a probe reads HI.
    #
    # FIX PATH, local to this fork's gem5 (no upstream PR): sign-extend the
    # 32-bit operands at the signed forms rather than widening the
    # zero-extended register -- `(int64_t)(int32_t)Rs_uw` in mult/div/madd/msub
    # at decoder.isa:186-206.  Not applied here: the gem5 build is shared with
    # the correct-path leg and with concurrent work, and rebuilding it under
    # them is an outward-facing change, not this leg's to make silently.
    'REF-MIPS32-SIGNED-ON-ZEXT':
        Rule('REF-MIPS32-SIGNED-ON-ZEXT', 'reference-defect', ANY,
             note='gem5 MIPS evaluates signed mult/div/madd/msub on the '
                  'zero-extended 32-bit register, yielding the unsigned '
                  'result in HI'),

    # The same wrong HI/LO read back out by mfhi/mflo.  Kept as its own label
    # because it is a PROPAGATION, not a second defect, and merging the two
    # would overstate how many gem5 mechanisms this leg found.
    'REF-MIPS32-SIGNED-ON-ZEXT-PROPAGATED':
        Rule('REF-MIPS32-SIGNED-ON-ZEXT-PROPAGATED', 'reference-defect', ANY,
             note='mfhi/mflo reading back the accumulator gem5 computed '
                  'through the zero-extended signed path'),

    # An FP arithmetic instruction READS the rounding mode and WRITES the
    # exception flags, so under R7 a pending write to FCSR must resolve before
    # it may proceed and its own flag write must be visible to a later cfc1.
    # gem5's MIPS publishes neither: `add.s` reaches its ExeTracer with the
    # destination FPR alone.  The edge is real and only the tracer states it.
    'REF-NO-FCSR-TRAFFIC':
        Rule('REF-NO-FCSR-TRAFFIC', 'reference-gap', {SUPERSET},
             note='gem5 MIPS does not publish the FCSR read (rounding mode) or '
                  'the FCSR write (exception flags) an FP operation performs'),

    # gem5 implements neither `pref`/`prefe` ("Prefetching not implemented for
    # MIPS") nor `synci` ("instruction 'synci' unimplemented"), so it names no
    # source, issues no request, and has nothing for either of the tracer's
    # runtime facts to disagree with.  Decided from gem5's OWN disassembly of
    # the instruction, not from the tracer's opcode class.
    'REF-HINT-UNIMPLEMENTED':
        Rule('REF-HINT-UNIMPLEMENTED', 'reference-gap', {SUPERSET},
             note='gem5 MIPS executes pref/prefe/synci as no-ops: no source '
                  'register, no memory request'),

    # BYTE-FOR-BYTE THE SAME ACCESSES, SPLIT DIFFERENTLY.  Measured, never
    # assumed: the label is emitted only when the two byte sets are EQUAL and
    # the request counts differ.  QEMU lowers the unaligned `lwl`/`lwr` and
    # `swl`/`swr` forms onto per-byte accesses; gem5 issues one sized request.
    # Neither is wrong about what the instruction touched, and the memop-addr
    # axis proves it by not firing.
    'SAME-BYTES-DIFFERENT-SPLIT':
        Rule('SAME-BYTES-DIFFERENT-SPLIT', 'vocabulary-difference',
             {SUPERSET, SUBSET, ORTHOGONAL},
             note='identical byte coverage, different number of requests'),

    # ------------------------------------------------------ emulation artefact
    # QEMU lowers store-conditional onto tcg_gen_atomic_cmpxchg, which really
    # reads the line.  The tracer records the access the guest PERFORMED under
    # QEMU; the architecture does not have it.  The riscv64 leg carries the
    # same shape on `sc` and the aarch64 leg on `stxr`.
    'QEMU-SC-CMPXCHG':
        Rule('QEMU-SC-CMPXCHG', 'emulation-artefact', {SUPERSET},
             note='store-conditional lowered onto a cmpxchg: the extra load is '
                  'an access the guest really made under QEMU'),

    # ------------------------------------------------------------- known defect
    # Kept because a rule that has stopped matching is the only way to notice a
    # regression: this fired on EVERY mipsel conditional branch before
    # 95a0d89e92, wearing the TRACER-SUPERSET direction the whole time.  It
    # accounts for nothing, so any row it labels stays UNACCOUNTED and the
    # headline goes red.
    'TRC-INVENTED-BRANCH-DEST':
        Rule('TRC-INVENTED-BRANCH-DEST', 'tracer-defect', {SUPERSET},
             accounts=False,
             note='mipsel conditional branches publishing a REG_GPR1 write the '
                  'instruction does not perform -- fixed at 95a0d89e92; a row '
                  'here is a regression'),
}


def mipsel_wp_rule(label):
    return MIPSEL_WP.get(label) if label else None
