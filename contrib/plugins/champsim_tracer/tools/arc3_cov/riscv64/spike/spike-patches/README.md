# Spike patches for the ARC 3 riscv64 execution leg

Upstream Spike's commit log is **destination-oriented**: it states what an
instruction wrote and where a store went, and is silent about what the
instruction *read*.  That silence bounded three facets of the riscv64
execution leg to `NONE` -- register sources, load data, load width -- and a
reference gap is not a verdict, so the reference is patched rather than
excused.

## Applies to

| | |
| --- | --- |
| upstream | `https://github.com/riscv-software-src/riscv-isa-sim` |
| revision | **`262df8bfac33b0419688429dd066487744db5c79`** (`Merge pull request #2380 from riscv-software-src/zvt`, 2026-08-19) |
| patch | `0001-commit-log-register-reads-and-load-data-width.patch` |

```sh
git -C riscv-isa-sim checkout 262df8bfac33b0419688429dd066487744db5c79
git -C riscv-isa-sim apply .../spike-patches/0001-commit-log-register-reads-and-load-data-width.patch
mkdir -p build && cd build && ../riscv-isa-sim/configure && make -j
```

The leg refuses to run against an unpatched Spike: `spike_ref.require_patched`
scans the commit log for the `read` and `memr` tokens and raises when they are
absent, so a stale binary reports as an error rather than as three axes that
quietly agree with nothing.

## What the patch adds, and where

### 1. Register READS -- at the decode site

`READ_REG` / `READ_FREG` in `riscv/decode_macros.h` are the funnel every
architectural source read of the integer and FP files passes through.  Both
now record `(name, value)` into a new `state_t::log_reg_read`, keyed with the
encoding `log_reg_write` already uses (`(num << 4) | bank`), under the same
`DECODE_MACRO_USAGE_LOGGED` guard the write side uses -- so the fast variant
of every instruction function is byte-for-byte unaffected and only the
`logged_*` variants pay anything.

Two constraints shaped the implementation and are worth keeping:

* The macros must remain **plain expressions**.  A statement-expression
  (`({...})`) breaks `get_field(READ_REG(x), mask)`, whose `decltype()` lands
  in a template-argument list.
* `DECODE_MACRO_USAGE_LOGGED` needs a default of `0` in the header, because
  `interactive.cc` uses the read macros outside any instruction body.
  `insn_template.cc` redefines it to the same token, which is an identical
  redefinition and therefore well-formed.

The other three banks are recorded at their own decode sites:

| bank | site | note |
| --- | --- | --- |
| `x` | `READ_REG`, `decode_macros.h` | x0 **is** recorded: an x0 source is a real fact about the encoding, unlike an x0 destination |
| `f` | `READ_FREG`, `decode_macros.h` | |
| `v` | `vectorUnit_t::elt` / `elt_group`, `is_write == false` | includes the mask register and the tail-undisturbed read of `vd` |
| CSR | `processor_t::get_csr`, `peek == false` | only the CSR a `csrr*` instruction addressed; the implicit `fcsr`/`vl` reads arithmetic makes through the `csr_t` objects directly are deliberately NOT recorded, because they are not operands |

A vector register is wider than `freg_t` and -- unlike a write -- its content
at commit time is not necessarily what was sourced, so vector reads are
snapshotted **whole, at read time**, into `state_t::log_vreg_read`.

### 2. Load DATA and WIDTH

`riscv/mmu.cc` pushed `(addr, 0, len)`: a literal zero in the data slot.  The
loaded bytes are in hand at that point (`load_slow_path_intrapage` has already
filled the buffer), so the real datum is now recorded, chunked exactly like
the store side so a wider access decomposes identically on both.

### 2b. The IMPLICIT source reads: fcsr, vl, vtype

Two dependences are architecturally real, are named by the tracer, and never
reach the commit log because Spike consumes them through the `csr_t` objects
rather than through `get_csr`:

* **fcsr.**  An instruction that rounds consults `frm`, and one that can raise
  an exception accrues into `fflags`.  Recorded at the two sites where the
  dependence arises -- `RM` and `set_fp_exceptions` -- and recorded
  *unconditionally* there, because the dependence belongs to the instruction
  and not to whether this particular execution happened to raise a flag.

  The obvious hook, `require_fp`, is **wrong** and was measured to be wrong:
  it is the FS-enable gate that every FP instruction passes, so it reported an
  fcsr source for eleven instructions that architecturally have none --
  `fmv.w.x`, `fmv.x.w`, `fsgnj.s`, `fsgnjn.s`, `fsgnjx.s`, `fclass.s`, and the
  FP loads and stores.  The tracer was right and the first version of this
  patch was wrong.

* **vl / vtype.**  A vtype-consuming vector instruction reads both to know its
  own shape; Spike reads them straight off the vector unit
  (`v_ext_macros.h`: `P.VU.vl->read()`).  Recorded at `require_vector`, the
  gate all of them pass.  `require_vector_novtype` deliberately records
  nothing: the instructions that use it are exactly the ones whose shape does
  not come from vtype.

### 3. The printer

`commit_log_print_insn` in `riscv/execute.cc` gains:

* ` read x5  0x…` / ` read f0  0x…` / ` read v1  0x…` / ` read c1_fflags 0x…`
  -- sources, under their own token so no existing consumer of the
  destination-oriented log can mistake a source for a destination, and so a
  parser never has to infer the role from arity;
* ` memr 0x<addr> 0x<data>` for loads.  The datum prints at `size << 3` bits,
  so the **width is recoverable from the hex digit count**, exactly as it
  already was for a store.

Stores keep their upstream ` mem 0x<addr> 0x<data>` spelling untouched.
