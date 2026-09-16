# riscv64 EXECUTION cross-check — ChampSim Tracer against Spike

Spike (`riscv-isa-sim`) as the riscv64 **execution** reference, 1 to 1 against a
real run.  `STATUS.md` §7 has named Spike the riscv64 execution reference since
the arc opened; until this harness it had never been wired in, and every
riscv64 attribution number came from the static (Sail) leg.

An execution reference gives what no static decoder can: the value that landed
in the destination register, the address the access went to, the bytes a store
wrote, the number of accesses an instruction actually made.  Static decode is
the fallback for what execution cannot reach, not the primary.

## The reference is PATCHED, and that is the point

Upstream Spike's commit log is **destination-oriented**.  It states what an
instruction wrote and where a store went, and it is silent about what the
instruction read; a load record carries a literal `0` where the datum should
be, and the printer emits only the address.  That silence bounded three facets
of this leg to `NONE` — register sources, load data, load width — and a
reference gap is not a verdict.  So the reference was changed.

`spike-patches/` holds the patch, the Spike revision it applies to
(`262df8bfac33b0419688429dd066487744db5c79`) and the reasoning for each hook.
`spike_ref.require_patched()` scans every commit log for the `read` and `memr`
tokens and raises when they are absent, so a stale binary reports as an error
rather than as three axes quietly agreeing with nothing.

## What the commit log exposes, after the patch

The whole contract, read off `riscv/execute.cc`, `riscv/mmu.cc` and
`riscv/decode_macros.h` rather than off the manual, because it bounds what
this leg is allowed to claim.

| fact | exposed? | where |
| --- | --- | --- |
| destination register + value (`x`/`f`/`v`/CSR) | yes | `execute.cc` `commit_log_print_insn` |
| **source** register + value (`x`/`f`/`v`/CSR) | yes — **patched in** | `decode_macros.h` `READ_REG`/`READ_FREG`, `vectorUnit_t::elt`, `processor_t::get_csr` |
| implicit **fcsr** dependence (rounding, flag accrual) | yes — **patched in** | `decode_macros.h` `RM` and `set_fp_exceptions` |
| implicit **vl/vtype** dependence | yes — **patched in** | `decode_macros.h` `require_vector` |
| memory **read** address, data **and** width | yes — **patched in** | `mmu.cc`; printed under `memr`, width from the hex digit count |
| memory **write** address, data **and** width | yes | `mmu.cc:406`; width from the hex digit count |
| privilege level of the retirement | yes | `commit_log_print_insn` |
| a **trapping** instruction | **NO** | `execute_insn_logged` prints only on completion |

Three consequences are load-bearing:

* **No axis on this leg reads "not measured".**  The three that used to are
  measured now, and the harness says so in its own report rather than leaving
  a reader to infer it.
* **Implicit CSR reads are recorded at the site the dependence arises, not at
  the enable gate.**  Hooking `require_fp` — which every FP instruction passes
  — reported an `fcsr` source for eleven instructions that architecturally
  have none (`fmv`, `fsgnj*`, `fclass`, and the FP loads and stores).  The two
  real sites are rounding (`RM`) and exception accrual (`set_fp_exceptions`),
  and both are recorded unconditionally there: the dependence belongs to the
  instruction, not to whether this execution happened to raise a flag.
* `-l` **without** `--log-commits` is still not a 1-to-1 stream:
  `processor_t::disasm` deduplicates a repeated `(pc, bits)` and summarises it
  as "Executed N times".  Only the commit lines are 1-to-1, and only they are
  parsed.

## Source VALUES: the wire carries none, so the model is what is checked

`format.rst` §5.4 is explicit — "source-register values are not emitted on the
wire; consumers reconstruct them from a regfile that the initial-state REGFILE
records and the DST_REG snapshots collectively define".  `tracer_log` performs
exactly that reconstruction, in execution order, and hands each instruction the
operand values a conforming consumer would have had.  Comparing **those**
against the reference's real reads is a genuine execution check rather than a
restatement of the trace: a wrong destination value, a missing width or a wrong
source-register name all surface as a wrong operand.

A register the model cannot value maps to `None` and is counted as
`model-unknown` — never silently zero, which would agree with the reference on
every zeroed register and manufacture a pass.  The report also states where
each operand value came from (`dst-snapshot` / `seed` / `arch-const`), because
a REGFILE seed that is never consulted is a claim nobody has tested.

## How a row is reported

Through `arc3_taxonomy`, like every other ARC 3 harness: a bare disagreement
count is not a result.  The register axis is split into **name** and **value**,
because compared as one set a wrong value reports as `ORTHOGONAL` — "different
vocabulary for the same fact" — which is exactly what a wrong value is not.  A
register both sides name, valued differently, is `TRACER-SUBSET` /
`tracer-defect` and lands in the headline.

CSRs are a third partition: the tracer folds several architectural CSRs onto
one `GenericRegId`, and that vocabulary question must not be allowed to dilute
the register-file result in either direction.

## The negative control is part of the result

`selftest_exec.py` perturbs one fact on one side of a real aligned pair and
requires the axis that owns that fact to go red.  An axis with no firing
mutation is reported `UNPROVEN` and its zero is not counted as a pass, because
a check that cannot fire reports agreement forever.  All **twelve** axes,
including the four the patched reference made possible, carry a mutation.

It has already earned its place twice:

* it reported `csr-dst-value` `UNPROVEN` rather than passing, because the
  mutation flipped `fflags[4:0]` while the reference named `frm[7:5]`;
* fixing that exposed a real bug in this harness — `w == 0` was being treated
  as a zero-byte field and masked to 0, which would have manufactured
  agreements and disagreements out of the harness's own arithmetic.

## Running

```sh
python compare_exec.py \
    --spike <spike> --pk <riscv-pk build>/pk \
    --qemu  <build>/qemu-riscv64 \
    --plugin <build>/contrib/plugins/libchampsim_tracer.so \
    --decode <build>/contrib/plugins/cst_decode \
    --dtc-dir <dir containing dtc> \
    -o <outdir> <guest ELF> [<guest ELF> ...]
```

Exit status is non-zero when `TRACER-SUBSET + UNACCOUNTED` is non-zero, when an
instruction is unaligned for a reason the trap log does not explain, or when
any axis is `UNPROVEN`.

`spike` must be the **patched** build (`spike-patches/`); an unpatched one is
refused by name.  It needs `dtc` on `PATH`.  `pk` is `riscv-pk`; with a `riscv64-linux-gnu`
toolchain it builds once an empty `gnu/stubs-lp64.h` is on the include path
(pk forces `-mabi=lp64` and is `-nostdlib`, so the ABI marker header is all
that is missing).  Spike must be given an `--isa` covering the guests —
`rv64gcv`, not `rv64gc`, or pk leaves `mstatus.VS` clear and every vector
instruction traps as illegal.

## The corpus

The validator's riscv64 generator emits a deliberately narrow vocabulary
(`add beqz ecall ld li lla ret sd xor`).  Agreement measured only over that is
a real result about a small part of the ISA, and quoting it as an ISA-wide one
would be survivorship bias.  `probes/mkprobes.py` builds seven further guests —
integer, sub-word memory, M, A, F/D, V, and control-transfer/compressed — in
the same shape as a validator guest (static, `-nostdlib`, `_start`, exit
`ecall`), so nothing in the pipeline needs a special case for them.

A probe may not read anything the two hosts are entitled to disagree about: no
`sp`/argv (pk and qemu lay the stack out differently), and no `cycle` / `time` /
`instret`.
