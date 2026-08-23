# riscv64 EXECUTION cross-check — ChampSim Tracer against Spike

Spike (`riscv-isa-sim`) as the riscv64 **execution** reference, 1 to 1 against a
real run.  `STATUS.md` §7 has named Spike the riscv64 execution reference since
the arc opened; until this harness it had never been wired in, and every
riscv64 attribution number came from the static (Sail) leg.

An execution reference gives what no static decoder can: the value that landed
in the destination register, the address the access went to, the bytes a store
wrote, the number of accesses an instruction actually made.  Static decode is
the fallback for what execution cannot reach, not the primary.

## What Spike's commit log exposes — and what it does not

The whole contract, read off `riscv/execute.cc` and `riscv/mmu.cc` rather than
off the manual, because it bounds what this leg is allowed to claim.

| fact | exposed? | where |
| --- | --- | --- |
| destination register + value (`x`/`f`/`v`/CSR) | yes | `execute.cc` `commit_log_print_insn` |
| privilege level of the retirement | yes | same |
| memory **read address** | yes | `mmu.cc:313` |
| memory **write** address, data **and width** | yes | `mmu.cc:406`; width recoverable from the hex digit count |
| **register reads** | **NO** | there is no `log_reg_read` at all |
| **load data** | **NO** | `mmu.cc:313` pushes `(addr, 0, len)`; the printer emits only the address |
| **load width** | **NO** | in the tuple, never printed |
| a **trapping** instruction | **NO** | `execute_insn_logged` prints only on completion |

Two consequences are load-bearing:

* **The read axis is not covered by this leg and no number here may be quoted
  as covering it.**  Spike's silence about sources is silence, not agreement.
  Register reads stay with the static (Sail) leg.
* `-l` **without** `--log-commits` is not a 1-to-1 stream:
  `processor_t::disasm` deduplicates a repeated `(pc, bits)` and summarises it
  as "Executed N times".  Only the commit lines are 1-to-1, and only they are
  parsed.

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
a check that cannot fire reports agreement forever.

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

`spike` needs `dtc` on `PATH`.  `pk` is `riscv-pk`; with a `riscv64-linux-gnu`
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
