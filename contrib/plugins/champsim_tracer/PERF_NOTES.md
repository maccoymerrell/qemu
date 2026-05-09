# Tracer profiling notes

## Optimization round 1 — encoder hot path

Targets identified by the profiling pass below were addressed in
champsim_tracer_output.cc and champsim_tracer_bb_template_cache.cc:

1. **`field_state_slot_index` → 256-byte lookup table.**  Replaced
   the eight-branch chain with a static `uint8_t` LUT built once at
   first `body_stream_new`.  Drops the function from a noticeable
   self-time line to a rounding error.

2. **`FieldStateTable` block cache: glib hash → `std::vector`.**
   Template IDs are dense small integers; indexing a vector by
   `template_id` replaces `g_hash_table_lookup` /
   `g_hash_table_insert` per body record with a single load.

3. **`emit_field_delta_section` per-entry scratch hoisted into
   `BodyStreamState`.**  Previously every body record allocated a
   fresh `g_new(StageRec, 16)` plus a fresh `GByteArray` for
   `rec_bw`; now `BodyStreamState` owns one of each, reused across
   millions of entries via length-reset rather than alloc/free.
   Eliminates the dominant per-entry malloc/free pair.

4. **`get_or_create_bb_template` scratch → `thread_local`.**  Per-
   call `g_new0` of `insn_pcs` / `insn_sizes` / `insn_bytes` /
   `insn_fields` / `insn_reg_names` showed up at ~3 % of total
   runtime even when the BB cache hit.  Replaced with `thread_local
   std::vector` scratch that grows once and is filled in place.

Measured impact on the `mcf_r` 20 M-instruction workload:

| Configuration  | Before  | After    | Saved        |
|----------------|---------|----------|--------------|
| cp_only        | 7.41 s  | 5.71 s   | 23 % (1.7 s) |
| wp_no_data     | 116 s   | 102.18 s | 12 % (13.8 s)|
| full           | 176 s   | 161.22 s | 8.4 % (14.8 s)|

The cp_only improvement is largest because the encoder-chain fixes
hit a higher fraction of total runtime when WP simulation isn't
running.  The wp_no_data improvement is smaller in percentage but
larger in absolute seconds saved (14 s).  Decode output remains
correct (verified by `cst_audit` + `cst_decode --format=legacy`).

Remaining hot spots after this pass (perf re-run on cp_only):

* `emit_field_delta_section` self time: 22 % (was 19 %; the
  function is now a larger fraction of total because cheaper
  surrounding code was removed).
* `__libc_calloc` + `_int_free` + `_int_malloc`: still ~12 %
  combined, mostly from `BBTemplateCache::commit_true_bb` building
  the canonical BB on first sighting (one-shot per BB) and from
  `DynParam` / `RegSnap` vector growth on hot body entries.
* `__tls_get_addr`: 4.3 % — still 4 thread-local accesses per
  `RegHandleCache::lookup` call.

Next round candidates (not yet implemented):

* Hoist the 4 thread-locals in `RegHandleCache::lookup` into a
  single `__tls_get_addr` invocation per call.
* Reserve `BodyEntry::dyn_params` and `BodyEntry::reg_snaps`
  capacity to typical sizes at construction so the per-record
  push_back path doesn't re-grow.
* Move the encoder off the vCPU thread (producer-consumer queue
  with raw `BodyEntry` payload) — once the per-entry encoder has
  been driven low enough that the worker can keep up at peak
  vCPU production rate.

---

## Optimization round 2 — reg-data path

`perf` had been mis-attributing the cost of the per-insn dst-reg
snap path: under sampling at 999 Hz the work was spread across so
many tiny call frames that no single self-time bar told the real
story.  Differential timing (progressively short-circuiting layers
of the path with an env-var knob) gave the actual breakdown on
the full config (`mcf_r 20 M`, `wp=1,memdata=1,regdata=1`):

| Skip level | What's bypassed (cumulative)                       | Wall    | Δ from prev |
|------------|----------------------------------------------------|---------|-------------|
| 0          | nothing (baseline)                                 | 163.83s | —           |
| 1          | `qemu_plugin_read_register` itself                 | 149.14s | −14.69s     |
| 2          | + `RegHandleCache::lookup` + scratch reset         | 134.25s | −14.89s     |
| 3          | + `pending_reg_snaps.push_back`                    | 125.34s | −8.91s      |
| 4          | + `capture_insn_snaps_live` wrapper entirely       | 124.54s | −0.80s      |

Total reg-data cost: **~39.3 s** (≈ 24 % of `full`), split nearly
evenly between the read API itself and the handle lookup, with a
smaller third in vector storage.  `perf` had pegged it at ≈ 22 s.

The lookup half was the actionable surprise.  Each instruction's
`InsnRegNames` was storing `QemuRegKey` **by value** (one copy per
slot), so the same logical register had a different key-pointer
across instructions, and the TLS pointer-identity cache in
`RegHandleCache::lookup` was missing ~50 % of the time and
falling through to the glib hash + `g_str_hash` + strcmp chain.

Fix: change `InsnRegNames::{src,dst}_qemu_reg_keys` and
`SyntheticEAInfo::{base,index}_key` to **pointers** into the
single global `g_qemu_reg_by_gen[]` table built by
`build_qemu_reg_reverse_index()` at install time.  Every reference
to logical register *gen_id* now uses the same pointer, so the
TLS pointer cache hits ~100 % cross-instruction.  Trace decode is
correct (`cst_audit` shows identical CP-entry / CP-insn / dst-reg
counts; the < 0.01 % delta in WP-entry counts is the libc-startup
cross-run variance noted in round 1).

Measured impact on `mcf_r 20 M` (re-baselined immediately before
the change):

| Configuration  | Before  | After    | Saved        |
|----------------|---------|----------|--------------|
| cp_only        | 5.92 s  | 5.03 s   | 15 % (0.9 s) |
| wp_no_data     | 102.0 s | 103.2 s  | within noise |
| full           | 161.6 s | 146.8 s  | 9.2 % (14.9 s)|

Tried and abandoned in this round:

* `-D_GLIBCXX_ASSERTIONS=0`, `-O3`, `-flto` for the plugin
  shared object: each ran inside ±3 % of baseline.  At `-O2`
  GCC has already done what's worth doing for this control-flow
  shape; the QEMU plugin API call boundary dominates.
* QEMU plugin API fast-path (`qemu_plugin_read_register_value`):
  added a per-target `gdb_read_register_value` hook that writes
  raw bytes into a caller-supplied buffer, skipping the
  `GByteArray + g_byte_array_append` chain.  Implemented for
  x86 / aarch64 / riscv / mips.  On top of the stable-keys
  change it saved a further ~5 s on `full` — not worth the
  ~22-file change to QEMU core for a 3 % improvement.  Reverted.
* `pending_reg_snaps` `assign`-out instead of `move`-out (to
  preserve underlying capacity across BBs): per-BB copy cost
  > realloc-avoidance saving.  Reverted.

Remaining big-ticket lever: the encoder still dominates on `full`
(see round 1 hot spots).  Moving `emit_body_entry` →
`emit_field_delta_section` off the vCPU thread onto a producer-
consumer worker pool is the next obvious round.

---



Run-time breakdown captured via `perf record -g --call-graph dwarf
-F 999` on a 5 M-instruction full-config (`wp=1,memdata=1,regdata=1,
wpdepth=64`) trace of `mcf_r_base.avx2-m64` (SPEC CPU2017 test
input) on x86_64.  Wall: 45.3 s for 5 M insns (~110 K insns/sec
trace throughput, ~979× slowdown vs an unmodified-QEMU stoptrigger
baseline).  `perf.data` had 44,576 samples.

## Top hotspots (self time)

| Self %  | Function                                              |
|---------|-------------------------------------------------------|
| 18.39 % | `emit_field_delta_section` (writer inner loop)        |
|  6.12 % | `simulate_wrong_path_ext`                             |
|  2.99 % | `__tls_get_addr` (in ld.so)                           |
|  2.75 % | `g_hash_table_lookup_extended`                        |
|  2.30 % | `g_hash_table_lookup`                                 |
|  2.25 % | `_int_malloc` / `_int_free` each                      |
|  1.92 % | `g_hash_table_insert`                                 |
|  1.87 % | `malloc` (libc)                                       |
|  1.82 % | `g_str_hash`                                          |
|  1.64 % | `field_state_slot_index`                              |
|  1.54 % | `MemAccessRecorder::record`                           |
|  1.46 % | `g_array_append_vals`                                 |
|  1.45 % | `emit_one_bb_delta_with_base`                         |
|  1.17 % | `thread_stats_get`                                    |
|  1.03 % | `RegSnapCollector::capture_insn_snaps_live`           |
|  0.91 % | `RegHandleCache::lookup`                              |

## Cumulative (children) time

| Children % | Function                                       |
|------------|------------------------------------------------|
|     63.29  | `vcpu_tb_exec` (inlined)                       |
|     38.30  | `emit_body_entry` (writer chain)               |
|     36.56  | `emit_body_record_payload`                     |
|     36.35  | `emit_one_bb_delta_with_base`                  |
|     33.93  | `emit_field_delta_section`                     |
|     24.12  | `simulate_wrong_path_ext` (WP simulator)       |
|     10.23  | `RegSnapCollector::capture_insn_snaps_live`    |
|      7.74  | `g_hash_table_insert`                          |
|      6.90  | `spec_store_bytes` (WP store buffer)           |
|      5.36  | `g_byte_array_append`                          |
|      4.31  | `RegHandleCache::lookup`                       |

## Diagnosis

The wire-format encoder is the single largest cost: **~38 % of
total runtime** lives inside the `emit_body_entry → ... →
emit_field_delta_section` chain.  Within that, the dominant
operations are:

* **Per-body-entry allocations.**  `emit_field_delta_section`
  starts every record with `g_autofree StageRec *stage = g_new(...,
  16)` plus `bw_init_buf(&rec_bw)` (a fresh GByteArray).  With
  ~500 K body entries on this 5 M-insn run, that's ~1 M
  malloc/free pairs just for the staging vec and rec buffer.
  malloc/free family adds up to **~10 %** of total runtime.
* **`g_hash_table_lookup` / `g_hash_table_insert`** for the
  per-template `FieldStateBlock` cache.  Lookup hits per body
  record × ~16 field descriptors with at least the lookup-once-
  per-entry pattern.  glib hash family adds up to **~10 %** of
  runtime.
* **`field_state_slot_index`** (1.6 % self time): a chain of 8
  if-comparisons mapping FID → slot index, called once per field
  probe.

The WP simulator is the second-largest contributor at **24 %
cumulative**.  The bulk of that is the spec-store-buffer machinery
(`spec_store_bytes`, `do_st8_mmu`) plus the WP simulator's own
self time (6 %); both inherent to the design.  WP iteration count
is bounded by `wpdepth`, so further savings here require either
dropping WP coverage or finding a cheaper way to drive QEMU's TCG
into spec mode.

The reg-data path (`RegSnapCollector::capture_insn_snaps_live` +
`RegHandleCache::lookup` + `read_into_snap`) is **~15 %
cumulative**.  Most of the cost is the QEMU plugin API call out
to `qemu_plugin_read_register` (which goes through
`gdb_read_register` + per-arch `gdb_read_register` callbacks).
The TLS access in `RegHandleCache::lookup` is 4 thread-locals
per call — `__tls_get_addr` shows up at 3 % self time, partly
from this site.

## Suggested optimizations, by expected impact

### Tier 1 — bulk allocator and hash-table churn (likely 15-25% speedup)

1. **Pre-allocate `StageRec[]` and `rec_bw` per BodyStreamState**
   (or thread-local).  Reset length to zero on each entry; reuse
   storage across millions of entries.  Eliminates the dominant
   malloc/free site in the encoder.

2. **Replace the `template_id → FieldStateBlock *` glib hash with
   a `std::vector<FieldStateBlock *>` indexed by `template_id`.**
   Template IDs are dense small integers assigned 1, 2, 3, ... by
   `BBTemplateCache`.  Direct array indexing replaces the
   `g_hash_table_lookup` + hash + bucket walk with a single load.

3. **Replace `field_state_slot_index` with a static 256-byte
   lookup table** populated at program start from the FID base /
   slot-count constants.  Branchless O(1) replaces 8-branch chain.

### Tier 2 — TLS hoisting and writer-side waste (likely 5-10% speedup)

4. **Cache `tls_cache_ / tls_ptr_cache_` addresses in stack-locals
   at function entry** of `RegHandleCache::lookup`.  Each call
   currently does 4 `__tls_get_addr` invocations; moving them to
   one apiece per call drops the TLS contribution by ~4×.

5. **Drop the `tls_*_cpu_index_` re-validation inside
   `RegHandleCache::lookup`.**  In QEMU user-mode the host thread
   running each callback is fixed for the lifetime of its vCPU,
   so the per-call check is dead weight after the first
   invocation.  Move it to `vcpu_init_cb` and assume thereafter.

6. **Hoist `g_wp_state` access in `vcpu_tb_exec`** — the
   thread-local has a non-trivial constructor (`TLS init function
   for g_wp_state` shows at ~1 %).  Cache the address once at
   `vcpu_init_cb` and read through that pointer in the hot path.

7. **Replace `bw_init_buf` / `bw_finish_buf` GByteArray pair with
   a fixed-capacity reusable scratch.**  Pre-grow once to a
   typical entry size; `g_byte_array_append` (5.4 % cumulative)
   is mostly the realloc path on a fresh small buffer.

### Tier 3 — design-level (10 %+ but more invasive)

8. **Async / pipelined encoder.**  Today the writer thread
   handles only on-disk I/O; the wire-format encoding runs
   synchronously in `vcpu_tb_exec`.  Moving the
   `emit_field_delta_section` loop off the hot path (queue raw
   `BodyEntry` to a worker thread, do the encoding there) would
   amortize the 38 % currently consuming the vCPU thread.
   Trade-off: more memory pressure (queued BodyEntry has
   per-record vectors), and more synchronization complexity.

9. **Skip the per-instruction `qemu_plugin_read_register` for
   destinations whose value is already in the QEMU plugin
   register-read API's existing payload.**  Currently each
   destination snapshot is one cross-API call.  If the
   pre-instruction inline-write callback already exposes the
   destination value (via the register-write tag), we could
   capture without the round-trip.  Open question — needs
   investigation.

## Reproducing

```sh
cd /path/to/build
ninja contrib/plugins/libchampsim_tracer.so contrib/plugins/cst_decode

cp /path/to/spec2017/505.mcf_r/data/test/input/* /tmp/
cd /tmp
perf record -g --call-graph dwarf -F 999 -o /tmp/perf.data -- \
  ./qemu-x86_64 \
  -plugin ./contrib/plugins/libchampsim_tracer.so,outfile=t,stop=5000000,wp=1,memdata=1,regdata=1 \
  /path/to/mcf_r_base.avx2-m64 inp.in

perf report -i /tmp/perf.data --stdio --children -n -g none | head -40
```
