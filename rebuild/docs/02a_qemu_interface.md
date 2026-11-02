# ChampSim Tracer — Layer 2a: the QEMU base interface

*Companion tab to Layer 2 (`02_shape.md`). The rebuild is a QEMU **fork** whose
plugin is only usable because the base carries a large, deliberate set of
modifications. Those modifications fall in two families the maintainer named —
**data-path classification** and **wrong-path support** — plus the system-mode
causality/identity surface and a few lifecycle hooks. This tab enumerates that
boundary as the rebuild's own view: for each interface, **what it is, the
intent, and a keep / change / rework verdict**. None of it is optional and none
is to be silently dropped — every entry below is a thing already fixed once, and
dropping it re-breaks that thing. The authoritative per-change detail is
`contrib/plugins/champsim_tracer/docs/qemu_modifications.rst` (cited `[qm §…]`);
this tab is the assessment layer on top, not a re-transcription.*

Receipts: `[qm §…]` = a section of `qemu_modifications.rst`; `[intent §…]` =
Layer 1; `[rule]` = a standing maintainer ruling; a bare `name()` is a plugin
API entry point.

---

## 0. The boundary principle (KEEP — it is the whole design)

QEMU is the **spec engine with a narrow exposure**; the plugin **derives**
everything from that exposure and from observed behaviour. Derivation inside the
translators is the violation the rebuild exists to remove. `[intent §1, §4.2]
[rule: intended-architecture]` So the interface is wide in *what QEMU states*
(decode facts, per-access provenance, resolved branch facts, privilege/asid,
thread pointer, path events) and narrow in *what the plugin computes from a
second decoder* — which is **nothing**: the in-tree tracer consults no Capstone
at runtime, and `disas/capstone.c` carries no fork change on the wire path
`[qm Plugin-API-additions; Disassembly-and-target-metadata]`. The one standing
licence on this boundary is the clean-rewrite rule: **the rebuild may change a
QEMU interface wherever that simplifies the plugin side** rather than clinging to
the current split `[rule: clean-rewrite]`. Section 7 is where that licence is
actually exercised.

`QEMU_PLUGIN_VERSION` is the advertised contract (currently 12 for the API-core
set, higher for later additions); the rebuild keeps a single version constant
and never overloads one number with two meanings — a lesson the shutdown-callback
history records the hard way `[qm Machine-shutdown-notification]`.

---

## 1. Data-path classification surface (KEEP; this is the zero-Capstone spine)

What the plugin reads to classify an instruction and attribute its operands —
all QEMU-stated, none re-derived.

| Interface | Intent | Verdict |
| --- | --- | --- |
| **Dataflow statement ABI** — per-instruction src/dst register sets, per-access address/data provenance, and the fold notes a decode site states (`insn_dataflow_declare_regfile`, `insn_dataflow_note_folded_reg`, the per-access provenance) | The opcode/registers/deps come from QEMU's own decode rules joined against one vocabulary table; "what the emulator refuses to execute is what the tracer refuses to record" | **KEEP** — the spine of §3.1/§3.4 intent `[qm Plugin-API-additions][intent §3.1,§3.4]` |
| **Static branch-target plumbing** — `qemu_plugin_insn_branch_target_pc()` + `plugin_gen_record_branch_target()` at every direct-branch decode site | The authoritative taken edge, per-ISA encoding already resolved by the translator (PC-relative/absolute, delay-slot, Thumb bit, RISC-V imm splits); Capstone's branch-immediate is not a safe substitute | **KEEP** — and it is *half* the deferred-structure answer (§7) `[qm Static-branch-target-plumbing]` |
| **Resolved conditional-branch direction** — the hook exposing QEMU's runtime-resolved arm (landed `59f8101261`/`572102ab1b`) | A coincident-edge branch (taken target == fall-through) reaches the same successor either way, so only the resolved direction distinguishes taken from not-taken; it is the carrier of `CST_FID_BRANCH_TAKEN` | **KEEP** — the other half of the branch deferral; a golden-fix that must be carried `[intent §3.5][format §5.6]` |
| **Synthetic-EA statement** — `insn_dataflow_note_synthetic_ea()` at the decode site, read back at exec time | Prefetch/cache-line/TLB-shootdown and `DC ZVA`/`CBO.ZERO`/`DC CVAU` translate to TCG no-ops (or helper loops), so their effective address must be *stated* and computed from base/index at exec; `ea = base + index_term + disp` | **KEEP** `[qm — Disassembly; format §5.2]` |
| **x86 lazy-flags resolution for plugin reads** — `cpu_compute_eflags()` on the gdbstub `IDX_FLAGS_REG` path + `gen_update_cc_op()` at `i386_tr_insn_start` under `plugin_enabled` | QEMU keeps CF/PF/AF/ZF/SF/OF in a lazy `cc_op` shadow; a mid-TB plugin read of `eflags` otherwise sees stale bits. Needed for a correct `CST_FID_METAFLAGS` | **KEEP** — a golden-class correctness fix the `metaflags` validator check surfaces `[qm x86-lazy-flags]` |
| **AArch64 PAN debug-read exemption** — `get_S1prot` skips PAN/PAN3/EPAN when `ptw->in_debug` | The content gate reads the marker bytes through `cpu_memory_rw_debug`; with `PSTATE.PAN` set a kernel-side read of a user VA returned "unreadable", gating the traced process off silently (measured: 19 of 384 user insns, ~1 boot in 16) | **KEEP** — a measured golden bug; carrying it is mandatory for system-mode identity `[qm AArch64-PAN]` |
| **Operand metadata extras** — `qemu_plugin_operand.segment_id` (x86 seg override), `.sysreg_class`, synthesised `.access` for AArch64 sysops / RISC-V CSRs | Address inputs and sysreg roles Capstone cannot express; they feed classification/deps | **KEEP** (but note: the Capstone decode-bug *workarounds* that also live at this boundary are the **offline referee's** now, not the wire's) `[qm Disassembly-and-target-metadata]` |
| **Register-name resolution sources** — `declare_regfile` (AArch64), `csr_ops` (RISC-V, 371 CSRs), MIPS GDB-XML build wiring | The regmap/gdbmap join from the target's own register declarations, so a control register without an adjudicated row fails the build rather than shipping a map one register short | **KEEP** `[arch: sysreg-operands][qm Disassembly]` |
| **Deterministic user-mode cycle/time reads** — `plugin_det_ticks` + per-target read-site gates (x86 RDTSC/RDTSCP, aarch64 CNTVCT/PMCCNTR, riscv rdcycle/rdtime/rdinstret), gated `qemu_plugin_any_loaded()` | A guest counter read is inside the determinism pin — QEMU owns and advances a synthetic per-vCPU tick, the plugin never feeds it; both paths read it | **KEEP** `[intent §3.9][qm Deterministic-user-mode-cycle/time-reads]` |

---

## 2. Wrong-path support surface (KEEP; the containment spine)

What makes a speculative excursion executable *and* side-effect-free. This is the
set the maintainer specifically flagged as not-to-be-dropped.

| Interface | Intent | Verdict |
| --- | --- | --- |
| **Spec-mode session** — `cpu_state_save`/`_restore`/`_free`, `spec_mode_begin`/`_end`, `set_pc`/`get_pc`, `exec_tb`, `spec_vtime_pause`/`_resume`, `spec_store_overflowed` | Enter a side-effect-suppressed execution mode at a wrong target, run one TB at a time with the full callback surface, roll architectural state back at chain end; the snapshot is sized by each target's `end_reset_fields` marker | **KEEP** `[qm Plugin-API-additions; Speculative-execution-support]` |
| **`end_reset_fields` marker** in `CPUArchState` (RISC-V + 7 other targets) | Delimits the rollback-eligible region so `cpu_plugin_arch_state_size()` copies exactly the architectural registers the WP writes; misplacement leaves a speculatively-corrupted register on the preserved side | **KEEP** `[qm Disassembly…/end_reset_fields]` |
| **Containment: `CF_FORCE_SLOW`** (i386 host backend) **+ portable `TLB_FORCE_SLOW`** (softmmu) **+ user-mode `tlb_vaddr_to_host`→NULL + `probe_access`→NULL** | Every speculative load/store routes to the slow `do_ld*`/`do_st*` helpers where the spec store buffer / load overlay live, instead of touching guest memory; `cpu_plugin_spec_mode_supported` is the capability gate (the one uncontained config — user-mode WP on a non-x86 host — refuses loudly) | **KEEP** — includes the **upstream user-mode `probe_access` defect fix** (FXSAVE/XRSTOR/CBO.ZERO correct-path memops were unreported before it) `[qm Speculative-execution-support; Speculative-execution-slow-path-routing]` |
| **Spec store buffer + atomic shadow** — per-vCPU `g_hash_table` keyed by 64-byte line (`PluginSpecLine`), `spec_atomic_shadow` for RMW, soft+hard caps | Store-to-load forwarding on the discarded path; an atomic is never handed the real host pointer (dropping an atomic means discard, never a real RMW); the soft budget flags a wild excursion for early termination | **KEEP** `[qm Speculative-execution-support/spec-store-buffer, atomic_mmu_lookup]` |
| **No speculation without paging** — `qemu_plugin_paging_enabled()` consulted before a walk | A real wrong-path fetch faults through the MMU; with paging off a branch into data is an unbounded NOP-sled that never seals. System-mode-only by construction | **KEEP** `[qm Bounding-wrong-path]` |
| **Device / global side-effect suppression** (per target: x86 port-IO/cr8/wrmsr, Arm `ARM_CP_IO`, RISC-V interrupt/timecmp, MIPS timer/VPE/`mfc0 $Random`) **+ MTRR/MCE & PMSA/SAU past-marker gating** | A privileged WP instruction's device poke or past-snapshot register write escapes the rollback; each is gated at its writer | **KEEP** — note the MIPS `$Random` and MTRR/PMSA cases are *reality-forced* (advancing them would change the correct path's TLB/config) `[qm Suppressing-device-and-global-side-effects]` |
| **Unsandboxable aborts** — halt family (mwait/wfi/wait), x86 SVM/SMM, `raise_interrupt2`, syscalls | A real wrong path would not retire deep past these either; each `cpu_loop_exit`s under spec mode, ending the walk | **KEEP** `[qm Aborting-unsandboxable-instructions]` |
| **WP syscalls: fetched, never performed** — user-mode unwind to the `exec_tb` landing pad + `do_syscall()` barrier; x86 system-mode `SYSCALL`/`SYSENTER` `cpu_loop_exit_restore` | The wrong path walks *past* a syscall at its fall-through; the call itself must never run. `WP host syscalls blocked` is the must-be-0 witness | **KEEP** `[qm Wrong-path-syscalls][intent §3.5]` |
| **MOPS spec clamp** — `MOPS_SPEC_MAX_BYTES`=256 in the FEAT_MOPS step helpers under spec mode | A MOPS helper loops a register-sized op inside one helper (no return to the plugin), so a speculative-garbage size register would drive billions of iterations | **KEEP** `[qm Speculative-execution-support/FEAT_MOPS][intent §3.3,§3.10]` |
| **Spec reserve + deferred flush** — `tcg_region` reserve, `plugin_flush_pending`, `request_tb_flush` deferral | A code-buffer overflow mid-walk must not reset the buffer under the nested correct-path TB (JIT SIGSEGV); the flush is deferred to a safe point. `WP chain cut by code-buffer` is the must-be-0 flush-invariance witness | **KEEP** `[qm Speculative-execution-support/tb_gen_code; Plugin-API-additions/request_tb_flush]` |
| **WP TLB-install log** — `plugin_spec_tlb_log`, invalidate only the pages an excursion installed | Avoids a full `tlb_flush` per excursion exit (ruinous at WP frequency) | **KEEP** `[qm Suppressing-device…/wrong-path-TLB-install-log]` |
| **host SIGBUS/SIGSEGV spec routing** — `cpu_loop_exit_sigsegv/sigbus` longjmp under spec mode; `host_sigbus_handler` `MMU_INST_FETCH` guard | A speculative fault must not queue a guest signal that later kills the correct path | **KEEP** — the sigbus guard is an upstream-QEMU fix the fork carries `[qm Speculative-execution-support]` |

---

## 3. Guest-time transparency surface (KEEP; the instrument-not-machine contract)

The tracer runs on the vCPU thread but is not guest execution; its host wall-clock
cost must never reach a guest clock. `[intent §3.8]`

| Interface | Intent | Verdict |
| --- | --- | --- |
| **vclock freeze** — `vclock_pause/_resume` (correct-path windows), `spec_vtime_pause/_resume` (whole excursion), `vclock_ns` read side | Freeze the guest virtual clock across instrumentation and the whole WP excursion; a wrong path consumes exactly zero guest time | **KEEP** `[qm Guest-time-transparency]` |
| **Processing-half stall** — `qemu_clock_plugin_stall_set`, `cpu_plugin_spec_ticks_freeze/_thaw` + `IcountFreeze` | Freezing the clock *value* alone leaves deadlines evaluated against a frozen value; the stall stops VIRTUAL deadline evaluation too, timers left armed on the list, delivered once at thaw. Deletes a family of per-ISA boundary re-evaluation patches | **KEEP** `[qm Guest-time-transparency]` |
| **`spec_clock_resync` (per target) + x86 TSC-lock-to-vclock** | On excursion exit every architectural counter, armed host timer, and interrupt line is reconciled to the frozen time; x86 removes the second oscillator rather than reconciling it (a golden-class drift fix) | **KEEP** `[qm Guest-time-transparency][intent §3.8]` |
| **vclock-agency** — slice bounding (`cst_bqslice`), consumption at slice breakout, the VIRTUAL exclusion, the halt rule | While a plugin instruments in system mode the vCPU class is the sole consumer of `QEMU_CLOCK_VIRTUAL`, removing the iothread's concurrent evaluator that every excursion races. This is the productized #106/#147 stall fix | **KEEP** — do not regress to the default-clock shape (that *is* the stall) `[qm Event-evaluation-agency]` |
| **Interrupt replay across rollback** — Arm `irq_line_state` carried whole, RISC-V `mip` externally-caused delta replayed, MIPS `Cause.IP7..2` complementary masks | An interrupt a controller asserted mid-excursion must survive the register rollback; a guest-caused `mip`/`sip` write is discarded with the speculative state | **KEEP** — these are golden-class WP-leak fixes (riscv MIP_MSIP erase, mipsel CP0_Cause loss) `[qm Interrupt-replay-across-the-wrong-path-rollback]` |
| **Device-timer re-arm bound** (`timerlist_run_timers` no-progress + ceiling) **+ MIPS GIC/R4K clamp + RISC-V itrigger module** | Upstream QEMU defects a frozen clock turns from latent to hard: a callback re-arming at `now` wedges the machine. Fixed on the fork with a proof test | **KEEP** — upstream-QEMU defects fixed locally (no upstream PR, per the standing ruling) `[qm Guest-time-transparency; RISC-V-instruction-count-trigger]` |

---

## 4. Path causality + identity surface (KEEP; system mode)

| Interface | Intent | Verdict |
| --- | --- | --- |
| **Path-event queue** — `plugin_evq` (FAULT_ENTER/RETURN, ASYNC_ENTER/RETURN, each stamped asid+priv), `cpu_events_set`/`drain`/`stats` + `cpu_events_pending_slot` | Delivers path causality as ordered events, not sampled state; the pending-slot makes "is a drain owed" JIT-testable so a drain point sits at every TB entry (bounds the grow-only queue); grow-only, never drops, spec-suppressed | **KEEP** — the channel the PathBuilder consumes `[qm Path-event-delivery][arch: path-builder]` |
| **Synchronous-fault stack** — `cpu_plugin_fault_push`/`pop` (exact resume-PC match), `plugin_fault_depth` | QEMU owns the resume-PC LIFO because it observes every fault entry/return synchronously; pushed only for re-executing faults | **KEEP** `[qm Path-event-delivery]` |
| **Async-interrupt window** — `plugin_in_async_int`/`async_int_reset`, `plugin_async_departure_pc` (compared with thread-ptr + root at re-fetch) | Marks the delivery-to-return window so async handlers are excluded by default; the reset exists for abandoned windows | **KEEP** `[qm Path-event-delivery][arch: async-exclusion]` |
| **System introspection** — `get_plugin_state` hook → `get_priv_level`/`get_addr_space_id`/`paging_enabled` | Privilege ordinal, address-space value (reported as a **label**, never an identity), MMU-on; per-target hook, user-mode defaults otherwise | **KEEP** `[qm Plugin-API-additions]` |
| **Thread identity** — `get_thread_ptr`, `thread_ptr_tracks_current` (per-sample), `set_current_task_offset` (`curtask_off=`), `vaddr_is_kernel` | Guest-thread identity independent of the vCPU, sampled at every privilege the target vouches for, so a kernel-internal context switch retags the strand; kernel code folds to one template via `vaddr_is_kernel` | **KEEP** `[intent §3.6][qm Plugin-API-additions][limits: kernel-strand]` |
| **Marker + gate plumbing** — `register_nosplit_code_sequences` (+ `translator.c` continue-through/retreat), `register_asid_write_cb`, `async_run_on_vcpu`, `in_spec_mode` | The marker TB is never split, so content-gate detection is one `memcmp` at translation; the asid-write callback fires even with the event queue disabled (coarse fast-forward); `async_run_on_vcpu` reads a vCPU's live context through its own thread | **KEEP** `[qm Never-split-code-sequences; Plugin-API-additions]` |
| **VA TB identity under plugins (no `CF_PCREL`)** — `tcg_cflags_set_pcrel` withholds the flag once a plugin is loaded | `CF_PCREL` drops the virtual PC from TB identity, so one TB serves every mapping of a shared page — and a per-instruction record minted under one mapping is reported at another process's addresses. Correct attribution is not negotiable | **KEEP** `[qm Virtual-address-TB-identity]` |
| **Disk-I/O ownership** — `register_devio_cb` (doorbell FIFO per vCPU) | Exact `(owner_thread, owner_asid)` on `DEVIO_START` under the canonical virtio-blk/ioeventfd-off config; positional fallback otherwise | **KEEP** (system-mode `devio=1` only) `[qm; format §4.1b]` |

---

## 5. Lifecycle surface (KEEP)

- **Machine-shutdown / reset notification** — `register_vm_shutdown_cb` (+ reset): the segment is finalised while the machine is still assembled, on a vCPU thread. The canonical system-mode terminator. The callback's version/argument history is a cautionary tale — one version number must never mean two callback shapes. `[qm Machine-shutdown-notification; Machine-reset-notification]`
- **MIPS MT** (a disabled processor still has one VPE running), **guest threads in user mode** (one `CPUState` per `clone`, so `thread_id` is the thread index), **deterministic guest input** (linux-user). All **KEEP**. `[qm MIPS-MT; Guest-threads-in-user-mode; Deterministic-guest-input]`
- **Build wiring** — `include/elf.h` build-attributes (RVC/RVV/TSO detection from the guest ELF), `linux-user/plugin-api.c` loader pull-in. **KEEP**. `[qm Build-wiring]`

---

## 6. The anti-drop ledger

Every group above is load-bearing; this is the explicit "do not silently drop"
table the rebuild checks itself against, with the consequence of dropping each.
The validation/lessons docs turn each row into a standing check.

| If this is dropped… | …this re-breaks |
| --- | --- |
| dataflow statement ABI | classification falls back to a second decoder — the exact thing the rebuild removed |
| branch-target + resolved-direction hooks | coincident-edge branches fabricate direction; indirect targets lost |
| synthetic-EA statement | prefetch/cache/TLB/DC-ZVA/CBO.ZERO carry no address (prefetcher research blind) |
| x86 lazy-flags resolution | every flag-writing x86 arith insn's metaflags are garbage |
| PAN debug-read exemption | ~1 boot in 16 silently traces ~5% of its instructions and closes clean |
| CF_FORCE_SLOW / TLB_FORCE_SLOW / probe_access | speculative stores (and correct-path FXSAVE/CBO.ZERO memops) leak to guest memory |
| no-speculation-without-paging | early-boot WP is a NOP-sled to OOM |
| device/global suppression | discarded WP permanently rewrites MTRR/PMSA/device/TLB-replacement state |
| spec_clock_resync / vclock-agency | guest time drifts; the #106 machine-wide stall returns |
| interrupt replay | riscv MIP/mipsel CP0_Cause interrupts dropped across every excursion |
| device-timer re-arm bound / itrigger | a legal guest timer program wedges the machine |
| path-event queue / fault stack | fault/async causality is sampled not ordered — the fault-split program order is unrecoverable |
| thread-ptr identity | kernel strands braid; per-thread attribution collapses |
| no-CF_PCREL | shared-page blocks attributed to the wrong process |
| shutdown notification | a marker-less system run never finalises its trace |

---

## 7. The one rework: retiring the deferred structure

The archetype the maintainer named. **The problem** is the pending-seal slot:
the plugin defers true-BB *N* to the dispatch of TB *N+1* because two facts are
only knowable one dispatch late — (a) the **tail instruction's post-execution
register snapshot** (an instruction's destination values are read by the *next*
instruction's callback; the TB's last instruction has no in-TB successor, so its
snapshot waits for the next TB), and (b) **which fragment actually executed and
its last PC** (resolved from the successor's inline `current_pc` store). That
one-dispatch deferral is the root of a whole class of close-time fabrication bugs
— a block flushed at a close publishes register values from the wrong moment
(#79) and a branch outcome it never observed (#81). `[arch: cp-flow, path-builder]`

**What is already solved and must not be re-opened:** the branch *target* (direct)
is captured in-instruction by `branch_target_pc`/`plugin_gen_record_branch_target`,
and the resolved *direction* by the `59f8101261` hook (§1). So the branch facts no
longer need the deferral; only the **register snapshot** and the
**executed-fragment resolution** still force it.

**The rework to assess (a new QEMU interface, not a plugin workaround):** a
**post-retirement per-instruction delivery** — QEMU hands the plugin an
instruction's committed destination-register values (and the fact that it
retired, and its own next-PC) *at that instruction*, after its TCG ops commit and
before the next instruction's translation-time callbacks, rather than the plugin
reading them one instruction late. QEMU knows the writeback set at op-emission
time; a post-insn callback firing on commit is the natural shape. Assess:

- **Does it remove the pending-seal slot entirely, or only the register half?**
  If the same callback (or a sibling per-fragment "this fragment retired, last
  PC = X" signal) also resolves which fragment executed, the slot and its
  one-dispatch lag disappear and the close-time fabrication class is designed out
  at the root. If only the register half is delivered, the fragment-resolution
  deferral remains and the slot stays — a smaller win. This is the central
  open question of the rework and Layer 2 must answer it against the code, not
  assume it.
- **Cost:** one callback per retired instruction only under `regdata=1`; measure
  against the current reg-snap-collector path (which already fires a per-insn
  callback on the *successor*).
- **Scope:** this is a wrong-path-aware interface — the same delivery must work
  inside `exec_tb` on the speculative path (where today the WP reg-snap falls
  back to a live post-fragment read for the trailing insn), so WP and CP use one
  mechanism.

This rework **adds** to the interface in this tab; it does not route around any
existing modification. Whether a second small rework is warranted — unifying the
two containment paths (`CF_FORCE_SLOW` vs the portable `TLB_FORCE_SLOW`) behind
one portable mechanism, so user-mode WP is no longer the single uncontained
configuration — is an **open assessment** for Layer 2, flagged here, not decided.

---

## 8. Golden-bug / correction cross-references (for the lessons + validation docs)

The QEMU-side modifications that were themselves **bug fixes** — carried so the
lessons doc verifies each is present in the rebuild, not only remembered:

- **upstream QEMU, fixed on the fork (no upstream PR, per the standing ruling):**
  user-mode `probe_access` dropping `TLB_MMIO` (correct-path FXSAVE/XRSTOR/CBO.ZERO
  memops unreported); `host_sigbus_handler` `MMU_INST_FETCH` guard; the
  device-timer re-arm wedge (MIPS GIC/R4K clamp); the RISC-V itrigger module (four
  defects); the x86 TSC/VIRTUAL two-oscillator drift.
- **content-gate / identity:** AArch64 PAN debug-read (measured 1-in-16 silent
  truncation).
- **WP state leaks:** riscv `MIP_MSIP` erased across an excursion; mipsel
  `CP0_Cause` IRQ loss — both closed by the interrupt-replay surface (§3).
- **data-path correctness:** x86 lazy-flags (every flag-writing arith insn's
  metaflags); the Capstone operand defects now owned entirely by the **offline
  referee**, never the wire.

Each belongs in the lessons doc's golden-bug ledger with its receipt and its
status *in the golden tree* (fixed-in-golden vs only-in-rebuild), per the
standing commitment. `[rule: golden-bug status]`
