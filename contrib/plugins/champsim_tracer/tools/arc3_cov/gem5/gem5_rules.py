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

    # The tracer publishes an address with NO WIDTH.  A prefetch's access
    # size is IMPLEMENTATION DEFINED, so the two tools need not agree on the
    # number -- but a width of 0 is not a different number, it is no number,
    # and a consumer cannot size the access from it.  Left for the maintainer.
    'MEMOP-WIDTH-UNSTATED':
        Rule('MEMOP-WIDTH-UNSTATED', 'needs-ruling', {SUBSET},
             note='same address, tracer states width 0; gem5 issues a sized '
                  'request'),

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

    # gem5's MIPS implements neither `pref`/`prefe` ("Prefetching not
    # implemented for MIPS") nor `synci` ("instruction 'synci' unimplemented"),
    # so it performs no access for them and has nothing for the tracer's
    # runtime memop to disagree with.  Note what this DOES settle: the
    # tracer's runtime record for these three carries a real address, which
    # is the half of W5 that the static binutils axis could not see.
    'HINT-MEMOP-REF-SILENT':
        Rule('HINT-MEMOP-REF-SILENT', 'reference-gap', {SUPERSET},
             note='gem5 MIPS executes pref/prefe/synci as no-ops and issues '
                  'no request'),

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
