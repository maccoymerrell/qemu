/*
 * QEMU CPU model
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */
#ifndef QEMU_CPU_H
#define QEMU_CPU_H

#include "hw/qdev-core.h"
#include "disas/dis-asm.h"
#include "exec/breakpoint.h"
#include "exec/hwaddr.h"
#include "exec/vaddr.h"
#include "exec/memattrs.h"
#include "exec/mmu-access-type.h"
#include "exec/plugin-spec.h"
#include "exec/tlb-common.h"
#include "qapi/qapi-types-machine.h"
#include "qapi/qapi-types-run-state.h"
#include "qemu/bitmap.h"
#include "qemu/rcu_queue.h"
#include "qemu/queue.h"
#include "qemu/lockcnt.h"
#include "qemu/thread.h"
#include "qom/object.h"

typedef int (*WriteCoreDumpFunction)(const void *buf, size_t size,
                                     void *opaque);

/**
 * SECTION:cpu
 * @section_id: QEMU-cpu
 * @title: CPU Class
 * @short_description: Base class for all CPUs
 */

#define TYPE_CPU "cpu"

/* Since this macro is used a lot in hot code paths and in conjunction with
 * FooCPU *foo_env_get_cpu(), we deviate from usual QOM practice by using
 * an unchecked cast.
 */
#define CPU(obj) ((CPUState *)(obj))

/*
 * The class checkers bring in CPU_GET_CLASS() which is potentially
 * expensive given the eventual call to
 * object_class_dynamic_cast_assert(). Because of this the CPUState
 * has a cached value for the class in cs->cc which is set up in
 * cpu_exec_realizefn() for use in hot code paths.
 */
typedef struct CPUClass CPUClass;
DECLARE_CLASS_CHECKERS(CPUClass, CPU,
                       TYPE_CPU)

/**
 * OBJECT_DECLARE_CPU_TYPE:
 * @CpuInstanceType: instance struct name
 * @CpuClassType: class struct name
 * @CPU_MODULE_OBJ_NAME: the CPU name in uppercase with underscore separators
 *
 * This macro is typically used in "cpu-qom.h" header file, and will:
 *
 *   - create the typedefs for the CPU object and class structs
 *   - register the type for use with g_autoptr
 *   - provide three standard type cast functions
 *
 * The object struct and class struct need to be declared manually.
 */
#define OBJECT_DECLARE_CPU_TYPE(CpuInstanceType, CpuClassType, CPU_MODULE_OBJ_NAME) \
    typedef struct ArchCPU CpuInstanceType; \
    OBJECT_DECLARE_TYPE(ArchCPU, CpuClassType, CPU_MODULE_OBJ_NAME);

typedef struct CPUWatchpoint CPUWatchpoint;

/* see physmem.c */
struct CPUAddressSpace;

/* see accel/tcg/tb-jmp-cache.h */
struct CPUJumpCache;

/* see accel-cpu.h */
struct AccelCPUClass;

/* see sysemu-cpu-ops.h */
struct SysemuCPUOps;

/**
 * CPUClass:
 * @class_by_name: Callback to map -cpu command line model name to an
 *                 instantiatable CPU type.
 * @parse_features: Callback to parse command line arguments.
 * @reset_dump_flags: #CPUDumpFlags to use for reset logging.
 * @mmu_index: Callback for choosing softmmu mmu index;
 *       may be used internally by memory_rw_debug without TCG.
 * @memory_rw_debug: Callback for GDB memory access.
 * @dump_state: Callback for dumping state.
 * @query_cpu_fast:
 *       Fill in target specific information for the "query-cpus-fast"
 *       QAPI call.
 * @get_arch_id: Callback for getting architecture-dependent CPU ID.
 * @set_pc: Callback for setting the Program Counter register. This
 *       should have the semantics used by the target architecture when
 *       setting the PC from a source such as an ELF file entry point;
 *       for example on Arm it will also set the Thumb mode bit based
 *       on the least significant bit of the new PC value.
 *       If the target behaviour here is anything other than "set
 *       the PC register to the value passed in" then the target must
 *       also implement the synchronize_from_tb hook.
 * @get_pc: Callback for getting the Program Counter register.
 *       As above, with the semantics of the target architecture.
 * @gdb_read_register: Callback for letting GDB read a register.
 *                     No more than @gdb_num_core_regs registers can be read.
 * @gdb_write_register: Callback for letting GDB write a register.
 *                     No more than @gdb_num_core_regs registers can be written.
 * @gdb_adjust_breakpoint: Callback for adjusting the address of a
 *       breakpoint.  Used by AVR to handle a gdb mis-feature with
 *       its Harvard architecture split code and data.
 * @gdb_num_core_regs: Number of core registers accessible to GDB or 0 to infer
 *                     from @gdb_core_xml_file.
 * @gdb_core_xml_file: File name for core registers GDB XML description.
 * @gdb_stop_before_watchpoint: Indicates whether GDB expects the CPU to stop
 *           before the insn which triggers a watchpoint rather than after it.
 * @gdb_arch_name: Optional callback that returns the architecture name known
 * to GDB. The returned value is expected to be a simple constant string:
 * the caller will not g_free() it.
 * @disas_set_info: Setup architecture specific components of disassembly info
 * @adjust_watchpoint_address: Perform a target-specific adjustment to an
 * address before attempting to match it against watchpoints.
 * @deprecation_note: If this CPUClass is deprecated, this field provides
 *                    related information.
 *
 * Represents a CPU family or model.
 */
struct CPUClass {
    /*< private >*/
    DeviceClass parent_class;
    /*< public >*/

    ObjectClass *(*class_by_name)(const char *cpu_model);
    void (*parse_features)(const char *typename, char *str, Error **errp);

    int (*mmu_index)(CPUState *cpu, bool ifetch);
    int (*memory_rw_debug)(CPUState *cpu, vaddr addr,
                           uint8_t *buf, size_t len, bool is_write);
    void (*dump_state)(CPUState *cpu, FILE *, int flags);
    void (*query_cpu_fast)(CPUState *cpu, CpuInfoFast *value);
    int64_t (*get_arch_id)(CPUState *cpu);
    void (*set_pc)(CPUState *cpu, vaddr value);
    vaddr (*get_pc)(CPUState *cpu);
    int (*gdb_read_register)(CPUState *cpu, GByteArray *buf, int reg);
    int (*gdb_write_register)(CPUState *cpu, uint8_t *buf, int reg);
    vaddr (*gdb_adjust_breakpoint)(CPUState *cpu, vaddr addr);

    const char *gdb_core_xml_file;
    const gchar * (*gdb_arch_name)(CPUState *cpu);

    void (*disas_set_info)(CPUState *cpu, disassemble_info *info);

    const char *deprecation_note;
    struct AccelCPUClass *accel_cpu;

    /* when system emulation is not available, this pointer is NULL */
    const struct SysemuCPUOps *sysemu_ops;

    /* when TCG is not available, this pointer is NULL */
    const TCGCPUOps *tcg_ops;

    /*
     * if not NULL, this is called in order for the CPUClass to initialize
     * class data that depends on the accelerator, see accel/accel-common.c.
     */
    void (*init_accel_cpu)(struct AccelCPUClass *accel_cpu, CPUClass *cc);

    /*
     * Keep non-pointer data at the end to minimize holes.
     */
    int reset_dump_flags;
    int gdb_num_core_regs;
    bool gdb_stop_before_watchpoint;
};

/*
 * Fix the number of mmu modes to 16, which is also the maximum
 * supported by the softmmu tlb api.
 */
#define NB_MMU_MODES 16

/* Use a fully associative victim tlb of 8 entries. */
#define CPU_VTLB_SIZE 8

/*
 * The full TLB entry, which is not accessed by generated TCG code,
 * so the layout is not as critical as that of CPUTLBEntry. This is
 * also why we don't want to combine the two structs.
 */
struct CPUTLBEntryFull {
    /*
     * @xlat_section contains:
     *  - in the lower TARGET_PAGE_BITS, a physical section number
     *  - with the lower TARGET_PAGE_BITS masked off, an offset which
     *    must be added to the virtual address to obtain:
     *     + the ram_addr_t of the target RAM (if the physical section
     *       number is PHYS_SECTION_NOTDIRTY or PHYS_SECTION_ROM)
     *     + the offset within the target MemoryRegion (otherwise)
     */
    hwaddr xlat_section;

    /*
     * @phys_addr contains the physical address in the address space
     * given by cpu_asidx_from_attrs(cpu, @attrs).
     */
    hwaddr phys_addr;

    /* @attrs contains the memory transaction attributes for the page. */
    MemTxAttrs attrs;

    /* @prot contains the complete protections for the page. */
    uint8_t prot;

    /* @lg_page_size contains the log2 of the page size. */
    uint8_t lg_page_size;

    /* Additional tlb flags requested by tlb_fill. */
    uint8_t tlb_fill_flags;

    /*
     * Additional tlb flags for use by the slow path. If non-zero,
     * the corresponding CPUTLBEntry comparator must have TLB_FORCE_SLOW.
     */
    uint8_t slow_flags[MMU_ACCESS_COUNT];

    /*
     * Allow target-specific additions to this structure.
     * This may be used to cache items from the guest cpu
     * page tables for later use by the implementation.
     */
    union {
        /*
         * Cache the attrs and shareability fields from the page table entry.
         *
         * For ARMMMUIdx_Stage2*, pte_attrs is the S2 descriptor bits [5:2].
         * Otherwise, pte_attrs is the same as the MAIR_EL1 8-bit format.
         * For shareability and guarded, as in the SH and GP fields respectively
         * of the VMSAv8-64 PTEs.
         */
        struct {
            uint8_t pte_attrs;
            uint8_t shareability;
            bool guarded;
        } arm;
    } extra;
};

/*
 * Data elements that are per MMU mode, minus the bits accessed by
 * the TCG fast path.
 */
typedef struct CPUTLBDesc {
    /*
     * Describe a region covering all of the large pages allocated
     * into the tlb.  When any page within this region is flushed,
     * we must flush the entire tlb.  The region is matched if
     * (addr & large_page_mask) == large_page_addr.
     */
    vaddr large_page_addr;
    vaddr large_page_mask;
#ifdef CONFIG_PLUGIN
    /*
     * The pair above, saved at wrong-path excursion entry and put back at
     * exit -- see cpu_plugin_spec_tlb_note(), which also records why these
     * moved here from file-scope arrays.  Per-mmu_idx AND per-vCPU because
     * that is what they shadow.
     */
    vaddr plugin_spec_lp_addr;
    vaddr plugin_spec_lp_mask;
#endif
    /* host time (in ns) at the beginning of the time window */
    int64_t window_begin_ns;
    /* maximum number of entries observed in the window */
    size_t window_max_entries;
    size_t n_used_entries;
    /* The next index to use in the tlb victim table.  */
    size_t vindex;
    /* The tlb victim table, in two parts.  */
    CPUTLBEntry vtable[CPU_VTLB_SIZE];
    CPUTLBEntryFull vfulltlb[CPU_VTLB_SIZE];
    CPUTLBEntryFull *fulltlb;
} CPUTLBDesc;

/*
 * Data elements that are shared between all MMU modes.
 */
typedef struct CPUTLBCommon {
    /* Serialize updates to f.table and d.vtable, and others as noted. */
    QemuSpin lock;
    /*
     * Within dirty, for each bit N, modifications have been made to
     * mmu_idx N since the last time that mmu_idx was flushed.
     * Protected by tlb_c.lock.
     */
    uint16_t dirty;
    /*
     * Statistics.  These are not lock protected, but are read and
     * written atomically.  This allows the monitor to print a snapshot
     * of the stats without interfering with the cpu.
     */
    size_t full_flush_count;
    size_t part_flush_count;
    size_t elide_flush_count;
#ifdef CONFIG_PLUGIN
    /*
     * True between cpu_plugin_spec_tlb_note() and
     * cpu_plugin_spec_tlb_flush_logged() on THIS vCPU: the large-page region
     * saved in CPUTLBDesc::plugin_spec_lp_* is valid and owed a restore.
     * Protected by @lock, like the tables it guards.
     */
    bool plugin_spec_lp_saved;
#endif
} CPUTLBCommon;

/*
 * The entire softmmu tlb, for all MMU modes.
 * The meaning of each of the MMU modes is defined in the target code.
 * Since this is placed within CPUNegativeOffsetState, the smallest
 * negative offsets are at the end of the struct.
 */
typedef struct CPUTLB {
#ifdef CONFIG_TCG
    CPUTLBCommon c;
    CPUTLBDesc d[NB_MMU_MODES];
    CPUTLBDescFast f[NB_MMU_MODES];
#endif
} CPUTLB;

/*
 * Low 16 bits: number of cycles left, used only in icount mode.
 * High 16 bits: Set to -1 to force TCG to stop executing linked TBs
 * for this CPU and return to its top level loop (even in non-icount mode).
 * This allows a single read-compare-cbranch-write sequence to test
 * for both decrementer underflow and exceptions.
 */
typedef union IcountDecr {
    uint32_t u32;
    struct {
#if HOST_BIG_ENDIAN
        uint16_t high;
        uint16_t low;
#else
        uint16_t low;
        uint16_t high;
#endif
    } u16;
} IcountDecr;

/**
 * CPUNegativeOffsetState: Elements of CPUState most efficiently accessed
 *                         from CPUArchState, via small negative offsets.
 * @can_do_io: True if memory-mapped IO is allowed.
 * @plugin_mem_cbs: active plugin memory callbacks
 * @plugin_mem_value_low: 64 lower bits of latest accessed mem value.
 * @plugin_mem_value_high: 64 higher bits of latest accessed mem value.
 */
typedef struct CPUNegativeOffsetState {
    CPUTLB tlb;
#ifdef CONFIG_PLUGIN
    /*
     * The callback pointer are accessed via TCG (see gen_empty_mem_helper).
     */
    GArray *plugin_mem_cbs;
    uint64_t plugin_mem_value_low;
    uint64_t plugin_mem_value_high;
#endif
    IcountDecr icount_decr;
    bool can_do_io;
} CPUNegativeOffsetState;

struct KVMState;
struct kvm_run;

/* work queue */

/* The union type allows passing of 64 bit target pointers on 32 bit
 * hosts in a single parameter
 */
typedef union {
    int           host_int;
    unsigned long host_ulong;
    void         *host_ptr;
    vaddr         target_ptr;
} run_on_cpu_data;

#define RUN_ON_CPU_HOST_PTR(p)    ((run_on_cpu_data){.host_ptr = (p)})
#define RUN_ON_CPU_HOST_INT(i)    ((run_on_cpu_data){.host_int = (i)})
#define RUN_ON_CPU_HOST_ULONG(ul) ((run_on_cpu_data){.host_ulong = (ul)})
#define RUN_ON_CPU_TARGET_PTR(v)  ((run_on_cpu_data){.target_ptr = (v)})
#define RUN_ON_CPU_NULL           RUN_ON_CPU_HOST_PTR(NULL)

typedef void (*run_on_cpu_func)(CPUState *cpu, run_on_cpu_data data);

struct qemu_work_item;

#define CPU_UNSET_NUMA_NODE_ID -1

/**
 * struct CPUState - common state of one CPU core or thread.
 *
 * @cpu_index: CPU index (informative).
 * @cluster_index: Identifies which cluster this CPU is in.
 *   For boards which don't define clusters or for "loose" CPUs not assigned
 *   to a cluster this will be UNASSIGNED_CLUSTER_INDEX; otherwise it will
 *   be the same as the cluster-id property of the CPU object's TYPE_CPU_CLUSTER
 *   QOM parent.
 *   Under TCG this value is propagated to @tcg_cflags.
 *   See TranslationBlock::TCG CF_CLUSTER_MASK.
 * @tcg_cflags: Pre-computed cflags for this cpu.
 * @nr_threads: Number of threads within this CPU core.
 * @thread: Host thread details, only live once @created is #true
 * @sem: WIN32 only semaphore used only for qtest
 * @thread_id: native thread id of vCPU, only live once @created is #true
 * @running: #true if CPU is currently running (lockless).
 * @has_waiter: #true if a CPU is currently waiting for the cpu_exec_end;
 * valid under cpu_list_lock.
 * @created: Indicates whether the CPU thread has been successfully created.
 * @halt_cond: condition variable sleeping threads can wait on.
 * @interrupt_request: Indicates a pending interrupt request.
 * @halted: Nonzero if the CPU is in suspended state.
 * @stop: Indicates a pending stop request.
 * @stopped: Indicates the CPU has been artificially stopped.
 * @unplug: Indicates a pending CPU unplug request.
 * @crash_occurred: Indicates the OS reported a crash (panic) for this CPU
 * @singlestep_enabled: Flags for single-stepping.
 * @icount_extra: Instructions until next timer event.
 * @cpu_ases: Pointer to array of CPUAddressSpaces (which define the
 *            AddressSpaces this CPU has)
 * @num_ases: number of CPUAddressSpaces in @cpu_ases
 * @as: Pointer to the first AddressSpace, for the convenience of targets which
 *      only have a single AddressSpace
 * @gdb_regs: Additional GDB registers.
 * @gdb_num_regs: Number of total registers accessible to GDB.
 * @gdb_num_g_regs: Number of registers in GDB 'g' packets.
 * @node: QTAILQ of CPUs sharing TB cache.
 * @opaque: User data.
 * @mem_io_pc: Host Program Counter at which the memory was accessed.
 * @accel: Pointer to accelerator specific state.
 * @kvm_fd: vCPU file descriptor for KVM.
 * @work_mutex: Lock to prevent multiple access to @work_list.
 * @work_list: List of pending asynchronous work.
 * @plugin_state: per-CPU plugin state
 * @ignore_memory_transaction_failures: Cached copy of the MachineState
 *    flag of the same name: allows the board to suppress calling of the
 *    CPU do_transaction_failed hook function.
 * @kvm_dirty_gfns: Points to the KVM dirty ring for this CPU when KVM dirty
 *    ring is enabled.
 * @kvm_fetch_index: Keeps the index that we last fetched from the per-vCPU
 *    dirty ring structure.
 *
 * @neg_align: The CPUState is the common part of a concrete ArchCPU
 * which is allocated when an individual CPU instance is created. As
 * such care is taken is ensure there is no gap between between
 * CPUState and CPUArchState within ArchCPU.
 *
 * @neg: The architectural register state ("cpu_env") immediately follows
 * CPUState in ArchCPU and is passed to TCG code. The @neg structure holds
 * some common TCG CPU variables which are accessed with a negative offset
 * from cpu_env.
 */
typedef enum QemuPluginCpuEventKind {
    QEMU_PLUGIN_CPU_EVENT_FAULT_ENTER  = 0,
    QEMU_PLUGIN_CPU_EVENT_FAULT_RETURN = 1,
    QEMU_PLUGIN_CPU_EVENT_ASYNC_ENTER  = 2,
    QEMU_PLUGIN_CPU_EVENT_ASYNC_RETURN = 3,
    /*
     * A committed architectural write that changed the address-space
     * register the target's get_plugin_state hook reports (MIPS
     * EntryHi.ASID, Arm TTBR0_EL1, RISC-V SATP, x86 CR3).  Field
     * semantics FOR THIS KIND differ from the fault/async kinds:
     * @asid is the NEW value just committed (the producer pushes after
     * the commit, so the event-instant stamp reads it), @pc carries the
     * OLD value it replaced (not a PC), @priv is the current privilege
     * and @depth_after the live plugin_fault_depth.  Produced only in
     * system-mode TUs, and only when the reported field's value
     * actually changes under the same masking get_plugin_state applies
     * (a MIPS EntryHi VPN-only write for TLB maintenance does not
     * emit).  Values must stay aligned with the public
     * qemu_plugin_cpu_event_kind enum: the drain passes kind through
     * raw.
     */
    QEMU_PLUGIN_CPU_EVENT_ASID_WRITE   = 4,
} QemuPluginCpuEventKind;

typedef struct QemuPluginCpuEvent {
    uint8_t  kind;          /* QemuPluginCpuEventKind */
    uint8_t  priv;          /* privilege level at the event instant */
    uint8_t  tp_ok;         /* @tp named the executing thread at the event
                             * instant (user privilege, or the target's
                             * tracks-current hook held in that state) */
    uint32_t depth_after;   /* plugin_fault_depth after applying the event */
    uint64_t pc;            /* resume PC (fault) / departure PC (async) */
    uint64_t asid;          /* address-space id at the event instant */
    uint64_t tp;            /* thread pointer at the event instant; for an
                             * ASYNC_ENTER, the DELIVERING thread's (pushed
                             * before any handler state switches) */
} QemuPluginCpuEvent;

/* The drain hands the buffer to plugins as struct qemu_plugin_cpu_event;
 * the two layouts must stay identical (checked in plugins/api.c). */

/*
 * STRUCTURAL ceiling on the queue length -- not a cap, not a threshold, and
 * nothing is ever dropped at it.  It is the value the length CANNOT reach
 * while the consumer contract below holds, so exceeding it is a broken
 * invariant and the producer says so loudly (cpu_plugin_evq_push).
 *
 * The consumer contract: the plugin registers a per-vCPU "queue non-empty"
 * scoreboard slot (qemu_plugin_cpu_events_pending_slot) and a per-TB
 * conditional callback on it, so EVERY translation block entry on that vCPU
 * is a drain point.  Between two consecutive drain points the producers are:
 *
 *   - the guest instructions of the ONE translation block in flight, each of
 *     which can commit at most one address-space-root write, and QEMU caps a
 *     TB at TCG_MAX_INSNS (512) instructions;
 *   - the exception edges that can be delivered without executing a TB in
 *     between: a fault entry, a fault return, an async entry and an async
 *     return.  A fault taken while delivering a fault nests, and that nesting
 *     is architecturally bounded -- the target resets long before it could
 *     exceed CPU_PLUGIN_FAULT_STACK_MAX (64) levels -- so at most
 *     2 * CPU_PLUGIN_FAULT_STACK_MAX edges can pile up unexecuted.
 *
 * 512 + 2*64 = 640; 1024 is that rounded up to the allocator's doubling
 * quantum, so the buffer reaches at most 1024 entries (32 KiB) per vCPU ONCE
 * and never grows again, independently of how long the vCPU runs untraced.
 */
#define CPU_PLUGIN_EVQ_STRUCTURAL_MAX 1024

typedef struct QemuPluginCpuEventQueue {
    QemuPluginCpuEvent *buf;    /* grow-only; owned by the vCPU */
    uint32_t len;
    uint32_t cap;
    bool enabled;
    /*
     * QUEUE-SIDE WITNESS.  Produced by the producer, upstream of every
     * plugin attribution decision, so a plugin gate that refuses a context
     * cannot suppress it.  max_len is the high-water length ever reached;
     * n_push / n_drain count the two ends.  Reported through
     * qemu_plugin_cpu_events_stats().
     */
    uint32_t max_len;
    uint64_t n_push;
    uint64_t n_drain;
} QemuPluginCpuEventQueue;

struct CPUState {
    /*< private >*/
    DeviceState parent_obj;
    /* cache to avoid expensive CPU_GET_CLASS */
    CPUClass *cc;
    /*< public >*/

    int nr_threads;

    struct QemuThread *thread;
#ifdef _WIN32
    QemuSemaphore sem;
#endif
    int thread_id;
    bool running, has_waiter;
    struct QemuCond *halt_cond;
    bool thread_kicked;
    bool created;
    bool stop;
    bool stopped;

    /* Should CPU start in powered-off state? */
    bool start_powered_off;

    bool unplug;
    bool crash_occurred;
    bool exit_request;
    int exclusive_context_count;
    uint32_t cflags_next_tb;
    /* updates protected by BQL */
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_budget;
    int64_t icount_extra;
    uint64_t random_seed;
    sigjmp_buf jmp_env;

    QemuMutex work_mutex;
    QSIMPLEQ_HEAD(, qemu_work_item) work_list;

    struct CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    struct CPUJumpCache *tb_jmp_cache;

    GArray *gdb_regs;
    int gdb_num_regs;
    int gdb_num_g_regs;
    QTAILQ_ENTRY(CPUState) node;

    /* ice debug support */
    QTAILQ_HEAD(, CPUBreakpoint) breakpoints;

    QTAILQ_HEAD(, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    void *opaque;

    /* In order to avoid passing too many arguments to the MMIO helpers,
     * we store some rarely used information in the CPU context.
     */
    uintptr_t mem_io_pc;

    /* Only used in KVM */
    int kvm_fd;
    struct KVMState *kvm_state;
    struct kvm_run *kvm_run;
    struct kvm_dirty_gfn *kvm_dirty_gfns;
    uint32_t kvm_fetch_index;
    uint64_t dirty_pages;
    int kvm_vcpu_stats_fd;
    bool vcpu_dirty;

    /* Use by accel-block: CPU is executing an ioctl() */
    QemuLockCnt in_ioctl_lock;

    /*
     * True while this vCPU is executing a plugin-driven wrong-path
     * (speculative) excursion.  Declared unconditionally, outside
     * CONFIG_PLUGIN, because the target and accelerator side effects it
     * suppresses are spread across ~20 translation units that read it from
     * plain architectural code paths (IRQ-line raises, timer re-arms, FERR#
     * assertion, TLB fills, ...).  Guarding each of those reads would put a
     * preprocessor conditional in the middle of otherwise ordinary target
     * logic; one always-present bool that is only ever set by the plugin
     * layer keeps those sites readable and keeps --disable-plugins building.
     * With CONFIG_PLUGIN undefined nothing can set it, so every such site
     * folds to its normal behaviour.
     */
    bool plugin_spec_mode;

#ifdef CONFIG_PLUGIN
    CPUPluginState *plugin_state;

    /*
     * Architectural self-loop accounting for the fan-out instruction (an
     * x86 REP-prefixed string operation) most recently executed on this
     * vCPU.  Both fields are written by target-generated TCG from the
     * instruction's own architectural state, never from how many
     * instrumentation callbacks a translation happened to deliver:
     *
     *   plugin_rep_iters     iterations this execution completed, taken
     *                        from the loop counter's own decrement
     *                        (CX/ECX/RCX per the address size).  A fault
     *                        inside an iteration leaves the count at the
     *                        iterations that actually retired.
     *   plugin_rep_complete  true when the repetition ended in this
     *                        execution: the loop counter reached zero, or
     *                        a REPZ/REPNZ flag condition broke it.  This is
     *                        the instruction's architectural retirement.
     *   plugin_rep_reenter   true when QEMU left this execution by jumping
     *                        back to the instruction's own address rather
     *                        than past it.  Unlike the two above this is an
     *                        implementation fact, and it is the one that
     *                        makes the artefact identifiable: a REP
     *                        translated as a single iteration re-enters
     *                        itself even after the iteration that retired
     *                        it, so the next execution performs zero
     *                        iterations and is the same instruction
     *                        finishing rather than a new one.
     *
     * These exist because a REP is not always translated as a loop.
     * do_gen_rep() emits exactly one iteration whenever CF_USE_ICOUNT,
     * CF_SINGLE_STEP, EFLAGS.TF or the interrupt shadow is in effect, and
     * a mid-instruction exception splits an already-looping REP the same
     * way.  A count inferred from delivered memory-op callbacks therefore
     * changes with the setting; these do not.  Read through
     * qemu_plugin_rep_iterations() / qemu_plugin_rep_complete().
     *
     * plugin_rep_pc names the instruction the pair describes, so a consumer
     * that reaches the accounting later than the execution it belongs to
     * (a deferred or merged emission) can tell and fall back rather than
     * attribute another instruction's count.  Targets with no fan-out
     * instruction never write it, which is also how a consumer recognises
     * that no architectural count is available at all.
     *
     * The name is an ADDRESS, and an address cannot say which PATH published
     * the value beside it.  That distinction is kept where it can be kept:
     * this whole block is saved and restored across a speculative excursion
     * with the rest of the wrong path's rollback (qemu_plugin_cpu_state_save
     * / _restore), so what a correct-path consumer reads was published by
     * correct-path execution.  Without that the invariant is unavailable to
     * any consumer at all -- an excursion is kicked from the end of the very
     * block a fan-out instruction terminates, and a speculative re-entry of
     * that same instruction republishes the same pc with a different count.
     *
     * plugin_rep_chunk qualifies plugin_rep_reenter: true when the re-enter
     * happened at a canonical chunk boundary — the point where do_gen_rep's
     * loop translation itself leaves the block every REP_MAX+1-and-change
     * iterations (counter writeback of the form 65536*m + 1, m >= 1).  A
     * loop translation only ever re-enters at such a boundary, so there the
     * flag is a translation-time constant; a single-iteration translation
     * computes it from the written-back counter.  It lets a consumer that
     * counts instructions the way a per-TB-execution counter does (e.g. the
     * bbv plugin feeding SimPoint) reproduce the canonical translation's
     * TB-entry count from any translation: keep re-entries with the flag,
     * discard re-entries without it.
     */
    uint64_t plugin_rep_iters;
    uint64_t plugin_rep_pc;
    bool plugin_rep_complete;
    bool plugin_rep_reenter;
    bool plugin_rep_chunk;

    /*
     * AArch64 FEAT_MOPS publishes through the same four fields — a
     * translate-time store of the instruction's address into
     * plugin_rep_pc plus the SET/CPY helpers' per-execution facts — but
     * its fan-out unit is one memory access, not an architectural
     * iteration, so plugin_rep_iters counts the accesses this execution
     * reported (each derived from the helper's own byte progress; see
     * arm_plugin_emit_pieces()).  plugin_rep_bytes is the architectural
     * anchor for that count: the bytes this execution moved, accumulated
     * from the step helpers' returns — the instruction's own
     * size-register decrement — so a consumer can verify the delivered
     * access stream against register-derived truth.  x86 REP leaves it 0.
     *
     * plugin_mops_report is the per-vCPU reporting-normalization
     * accumulator the FEAT_MOPS byte fallbacks use (owned by
     * target/arm/tcg/helper-a64.c; lazily allocated, vCPU lifetime).  It
     * carries a pending partially-reported run across the cpu_loop_exit
     * and fault splits of one bulk instruction, which is what keeps the
     * reported decomposition identical however the execution was split.
     */
    uint64_t plugin_rep_bytes;
    void *plugin_mops_report;

    /* Wrong-path speculative execution state.  Sandbox is indexed by
     * cache-line address (64-byte aligned) — an 8-byte store costs
     * one hash op instead of eight, and a vector store within a line
     * collapses to a memcpy + mask update.  Lines are bump-allocated
     * from plugin_spec_store_pool so spec_mode_end can release
     * entries by truncating the pool without per-line g_free traffic.
     * Hash value type is the line's POOL INDEX + 1 (see
     * spec_line_get_or_alloc: the pool moves when it grows, so a stored
     * pointer would dangle; an index survives the realloc).
     * plugin_spec_mode itself lives outside CONFIG_PLUGIN (see above). */
    GHashTable *plugin_spec_store_buf;        /* line_addr -> pool idx + 1 */
    void *plugin_spec_store_pool;             /* PluginSpecLine[] */
    size_t plugin_spec_store_pool_used;       /* high water in pool */
    size_t plugin_spec_store_pool_cap;        /* allocated slots */
#ifdef CONFIG_PLUGIN
    /*
     * Discard target for a speculative atomic RMW that could not be given a
     * sandbox line (the line pool is at PLUGIN_SPEC_STORE_LINE_MAX and this
     * line is not already tracked).  The RMW needs somewhere real to operate
     * — the host atomic primitives write through the pointer they are handed
     * — and the one place it must never be is guest memory, so it is pointed
     * at this scratch line instead and the result is dropped, which is how a
     * capped speculative *store* already degrades.  Per-vCPU rather than
     * thread-local: under round-robin TCG several vCPUs share one host
     * thread, and a discard buffer that is shared across vCPUs is a fact a
     * reader has to re-derive as harmless every time.  See
     * spec_atomic_shadow() in accel/tcg/internal-common.h.
     */
    PluginSpecLine plugin_spec_atomic_scratch;
#endif
    /* Set when a single wrong-path excursion's speculative-store footprint
     * crosses PLUGIN_SPEC_STORE_SOFT_BUDGET lines — a garbage-size memop the
     * wrong path executed without faulting (it is buffered, not real).  The WP
     * loop polls qemu_plugin_spec_store_overflowed() and terminates the
     * excursion rather than filling the buffer to the hard cap and dropping
     * stores.  Cleared per excursion in qemu_plugin_spec_mode_begin. */
    bool plugin_spec_store_overflow;
    struct qemu_plugin_cpu_state *plugin_spec_saved_state;
    /*
     * Set when a code-buffer overflow is detected DURING wrong-path
     * (plugin_spec_mode) translation.  A real tb_flush there would reset the
     * code buffer under the correct-path TB this wrong-path walk is nested
     * inside, clobbering the host code we must return into.  Instead the
     * overflow is deferred: the wrong-path walk ends cleanly at its current
     * true-BB boundary and the flush is honored by cpu_exec_loop() at the
     * next safe point, after the nested walk has fully unwound.
     */
    bool plugin_flush_pending;
    /*
     * Set while the guest virtual clock is paused for a wrong-path excursion
     * (qemu_plugin_spec_vtime_pause/resume).  Keeps the pause idempotent and
     * balanced across a fault-skip's spec_mode teardown/re-entry, so the
     * excursion's host wall-clock time never leaks into the guest's
     * architected counters.
     */
    bool plugin_spec_vtime_paused;
    /* An excursion WP-dispatch cleared a pending kick (icount_decr.u16.high
     * was nonzero at the clear).  Consumed by the edge-semantics re-arm. */
    bool plugin_spec_kick_deferred;
    /*
     * Nesting depth of qemu_plugin_vclock_pause/resume: freezes the guest
     * virtual clock while a plugin runs instrumentation work on the vCPU
     * thread (translation-time decoding, per-TB trace emission).  That work
     * is outside guest execution, so its host wall-clock cost must not be
     * charged to guest time: if one guest timer-tick handler's instrumented
     * cost exceeds the tick period, the next tick is already pending when
     * the handler returns and the guest collapses into a self-sustaining
     * tick/scheduler storm (RCU stall, zero foreground progress).  Composes
     * with plugin_spec_vtime_paused: ticks re-enable only when BOTH say so.
     */
    int plugin_vclock_depth;
    /*
     * Asynchronous-interrupt exclusion for system-mode tracing.  The target's
     * exception-delivery path sets plugin_in_async_int=true on an ASYNCHRONOUS
     * interrupt entry (timer/device IRQ/FIQ/SError), recording the interrupted
     * guest PC (the departure point, where the handler's exception return will
     * resume) in plugin_async_departure_pc.  The exception-return path clears
     * the flag when it returns to exactly that PC — robust to the scheduler
     * context-switching away and to nesting (the outermost departure PC is
     * kept).  A tracer reads the flag (qemu_plugin_in_async_int) to drop the
     * async handler — non-representative OS noise — while keeping synchronous
     * syscalls/faults.  Set only on the correct path (never wrong-path).
     *
     * The departure CONTEXT is recorded alongside the departure PC: the
     * guest thread-pointer register (TCGCPUOps::get_plugin_thread_ptr — the
     * same register a tracer derives guest-thread identity from).  The
     * return check compares it at the departure-PC re-fetch, because under
     * SMP a PEER thread executing the same VA must not close another
     * thread's window: a genuine resume restores the departed thread's
     * whole context (the thread pointer included) before landing on the
     * departure PC, so equality is exact there, while a peer at the same VA
     * carries its own thread pointer and is skipped.  Targets without the
     * hook record 0 and the check degrades to the bare PC equality.
     */
    bool plugin_in_async_int;
    uint64_t plugin_async_departure_pc;
    uint64_t plugin_async_departure_tp;
    /*
     * Synchronous-fault excursion reporting for system-mode tracing.  Unlike
     * the async path above, sync faults are KEPT (the handler is real,
     * workload-induced kernel code), but the tracer needs to know (a) that a
     * fault detoured execution and (b) how deeply nested it is, so it can emit
     * the handler as first-class code at a nesting depth and resume the
     * faulting BB as a whole block afterwards.
     *
     * QEMU owns the resume-PC stack directly (cpu_plugin_fault_push/pop), which
     * it can maintain ACCURATELY because it observes every entry and every
     * exception-return synchronously and in strict LIFO order.
     *
     * cpu_plugin_fault_push (each target's do_interrupt, for a RE-EXECUTING
     * fault only -- TLB/coprocessor-lazy-enable, NOT syscall/advance-past)
     * pushes the resume PC (the faulting instruction, where the handler's
     * exception-return lands) and bumps plugin_fault_depth.
     * cpu_plugin_fault_pop (each target's exception-return path) pops the top
     * IFF the return target equals it -- so syscall/async returns, which never
     * pushed, don't disturb the stack.  Both are no-ops on the wrong path
     * (plugin_spec_mode).  Each push/pop also appends an ordered
     * FAULT_ENTER/FAULT_RETURN event to the queue below — the channel a
     * plugin consumes the transitions through; plugin_fault_depth is the
     * authoritative live nesting depth (qemu_plugin_fault_depth()).
     */
#define CPU_PLUGIN_FAULT_STACK_MAX 64
    uint64_t plugin_fault_stack[CPU_PLUGIN_FAULT_STACK_MAX];
    uint32_t plugin_fault_depth;      /* == number of live pushed faults */
    /*
     * Ordered per-vCPU path-event queue.  Delivers path causality as
     * ORDERED EVENTS: each fault entry/return and async-window edge is
     * appended at its chokepoint, with (asid, priv) stamped at the event
     * instant.  Single producer and single consumer — the owning vCPU
     * thread — so no locking; grow-only, never drops; spec-mode-suppressed
     * at source like everything else here.  Disabled (and empty) unless a
     * plugin opts in via qemu_plugin_cpu_events_set().
     */
    QemuPluginCpuEventQueue plugin_evq;
    /*
     * Wrong-path TLB-install log.  Speculative (wrong-path) accesses can
     * install softmmu TLB entries on a miss.  Rather than a full tlb_flush()
     * on every excursion exit — which drops the ENTIRE correct-path TLB plus
     * the jump cache, ruinously expensive given how often WP runs — we record
     * the pages an excursion installed (in tlb_set_page_full) and invalidate
     * only those on exit.  When WP merely HITS existing entries (the common
     * case) the log stays empty and no flush happens at all.  mmu_idx encodes
     * the translation regime, so recording the actual install mmu_idx also
     * covers the wrong-path-changed-EL (eret) concern.  A large-page install or
     * log overflow falls back to a full flush.
     */
#define CPU_SPEC_TLB_LOG_MAX 64
    struct {
        vaddr page;
        uint16_t mmu_idx;
    } plugin_spec_tlb_log[CPU_SPEC_TLB_LOG_MAX];
    uint16_t plugin_spec_tlb_log_n;
    bool plugin_spec_tlb_log_overflow;
    /*
     * Wrong-path speculative absent-page sentinel (softmmu).  A speculative
     * access to a genuinely-absent page must neither raise a guest fault nor
     * demand-page, but it also must NOT truncate the excursion: on a
     * mispredicted path no instruction retires, so a back-end memory fault is
     * never taken by a real core.  tlb_fill_align sets this instead of
     * longjmping; the immediate caller (mmu_lookup1 / atomic_mmu_lookup)
     * consumes and clears it, substituting a deterministic placeholder value
     * (plugin_spec_garbage_fill) and continuing.  Transient — never observed
     * across a memory-op boundary.
     */
    bool plugin_spec_absent;
    /*
     * Set by the garbage-filling wrong-path load/store path (user-exec twin and
     * softmmu) for the current speculative access when it landed on an
     * absent/unreadable page and read a synthetic placeholder.  The plugin's
     * memory callback reads and clears it (qemu_plugin_spec_mem_faulted_take)
     * to tag that memop as a synthetic-data fault in the wrong-path trace.
     */
    bool plugin_spec_mem_faulted;
#endif

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    int cluster_index;
    uint32_t tcg_cflags;
    uint32_t halted;
    int32_t exception_index;

    AccelCPUState *accel;

    /* Used to keep track of an outstanding cpu throttle thread for migration
     * autoconverge
     */
    bool throttle_thread_scheduled;

    /*
     * Sleep throttle_us_per_full microseconds once dirty ring is full
     * if dirty page rate limit is enabled.
     */
    int64_t throttle_us_per_full;

    bool ignore_memory_transaction_failures;

    /* Used for user-only emulation of prctl(PR_SET_UNALIGN). */
    bool prctl_unalign_sigbus;

    /* track IOMMUs whose translations we've cached in the TCG TLB */
    GArray *iommu_notifiers;

    /*
     * MUST BE LAST in order to minimize the displacement to CPUArchState.
     */
    char neg_align[-sizeof(CPUNegativeOffsetState) % 16] QEMU_ALIGNED(16);
    CPUNegativeOffsetState neg;
};

/* Validate placement of CPUNegativeOffsetState. */
QEMU_BUILD_BUG_ON(offsetof(CPUState, neg) !=
                  sizeof(CPUState) - sizeof(CPUNegativeOffsetState));

#ifdef CONFIG_PLUGIN
/*
 * System-mode synchronous-fault excursion stack (see the plugin_fault_* fields
 * above).  Each target's do_interrupt calls _push for a RE-EXECUTING fault
 * (the handler's ERET lands back on @resume_pc); each target's exception-return
 * path calls _pop with the ERET target.  QEMU maintaining this synchronously
 * is what makes the tracer's fault depth exact under dense nested faults.
 */
/* Append one path event to @cpu's plugin event queue (no-op while the
 * queue is disabled or on the wrong path).  Defined in plugins/core.c,
 * where the per-target get_plugin_state hook is reachable for stamping
 * (asid, priv) at the event instant. */
void cpu_plugin_evq_push(CPUState *cpu, int kind, uint64_t pc,
                         uint32_t depth_after);

/* Open an asynchronous-interrupt window: set plugin_in_async_int, record
 * the departure context (@departure_pc = where the handler's exception
 * return resumes, plus the thread-pointer register naming the departing
 * thread) and append the ordered ASYNC_ENTER event.  Callers gate on the
 * edge (!plugin_in_async_int) and on the correct path (!plugin_spec_mode);
 * defined in plugins/core.c, where the per-target hooks are reachable. */
void cpu_plugin_async_enter(CPUState *cpu, uint64_t departure_pc);

/* Condition instrument (CST_ASYNCPROD_DIAG), called by each target's
 * do_interrupt for EVERY delivery it classifies, before the correct-path /
 * outermost-edge gates: reports which vCPU received which exception in what
 * state (spec mode, an async window already open, event queue enabled), so a
 * window that never opens can be told apart from one that opens and is never
 * consumed.  A no-op unless the variable is set; never changes behaviour. */
void cpu_plugin_async_probe(CPUState *cpu, const char *tag, int exc_index,
                            bool is_async);

static inline void cpu_plugin_fault_push(CPUState *cpu, uint64_t resume_pc)
{
    if (cpu->plugin_spec_mode) {
        return;   /* wrong-path faults must not perturb the real stack */
    }
    if (cpu->plugin_fault_depth < CPU_PLUGIN_FAULT_STACK_MAX) {
        cpu->plugin_fault_stack[cpu->plugin_fault_depth] = resume_pc;
    }
    cpu->plugin_fault_depth++;   /* saturating read is fine; depth caps effect */
    cpu_plugin_evq_push(cpu, QEMU_PLUGIN_CPU_EVENT_FAULT_ENTER, resume_pc,
                        cpu->plugin_fault_depth);
}

static inline void cpu_plugin_fault_pop(CPUState *cpu, uint64_t target_pc)
{
    if (cpu->plugin_spec_mode || cpu->plugin_fault_depth == 0) {
        return;
    }
    /*
     * Pop only when this exception-return lands on the top frame's resume PC.
     * A syscall/async return (which never pushed) targets somewhere else, so it
     * leaves the fault stack untouched.  Every pushed fault re-executes its
     * faulting instruction, so its ERET target always equals the pushed PC --
     * the match is exact, not heuristic.
     */
    uint32_t top = cpu->plugin_fault_depth - 1;
    if (top < CPU_PLUGIN_FAULT_STACK_MAX &&
        cpu->plugin_fault_stack[top] != target_pc) {
        return;
    }
    cpu->plugin_fault_depth--;
    cpu_plugin_evq_push(cpu, QEMU_PLUGIN_CPU_EVENT_FAULT_RETURN, target_pc,
                        cpu->plugin_fault_depth);
}
#endif /* CONFIG_PLUGIN */

static inline CPUArchState *cpu_env(CPUState *cpu)
{
    /* We validate that CPUArchState follows CPUState in cpu-all.h. */
    return (CPUArchState *)(cpu + 1);
}

typedef QTAILQ_HEAD(CPUTailQ, CPUState) CPUTailQ;
extern CPUTailQ cpus_queue;

#define first_cpu        QTAILQ_FIRST_RCU(&cpus_queue)
#define CPU_NEXT(cpu)    QTAILQ_NEXT_RCU(cpu, node)
#define CPU_FOREACH(cpu) QTAILQ_FOREACH_RCU(cpu, &cpus_queue, node)
#define CPU_FOREACH_SAFE(cpu, next_cpu) \
    QTAILQ_FOREACH_SAFE_RCU(cpu, &cpus_queue, node, next_cpu)

extern __thread CPUState *current_cpu;

/**
 * qemu_tcg_mttcg_enabled:
 * Check whether we are running MultiThread TCG or not.
 *
 * Returns: %true if we are in MTTCG mode %false otherwise.
 */
extern bool mttcg_enabled;
#define qemu_tcg_mttcg_enabled() (mttcg_enabled)

/**
 * cpu_paging_enabled:
 * @cpu: The CPU whose state is to be inspected.
 *
 * Returns: %true if paging is enabled, %false otherwise.
 */
bool cpu_paging_enabled(const CPUState *cpu);

#if !defined(CONFIG_USER_ONLY)

/**
 * cpu_get_memory_mapping:
 * @cpu: The CPU whose memory mappings are to be obtained.
 * @list: Where to write the memory mappings to.
 * @errp: Pointer for reporting an #Error.
 *
 * Returns: %true on success, %false otherwise.
 */
bool cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list,
                            Error **errp);

/**
 * cpu_write_elf64_note:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf64_note(WriteCoreDumpFunction f, CPUState *cpu,
                         int cpuid, void *opaque);

/**
 * cpu_write_elf64_qemunote:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf64_qemunote(WriteCoreDumpFunction f, CPUState *cpu,
                             void *opaque);

/**
 * cpu_write_elf32_note:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf32_note(WriteCoreDumpFunction f, CPUState *cpu,
                         int cpuid, void *opaque);

/**
 * cpu_write_elf32_qemunote:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf32_qemunote(WriteCoreDumpFunction f, CPUState *cpu,
                             void *opaque);

/**
 * cpu_get_crash_info:
 * @cpu: The CPU to get crash information for
 *
 * Gets the previously saved crash information.
 * Caller is responsible for freeing the data.
 */
GuestPanicInformation *cpu_get_crash_info(CPUState *cpu);

#endif /* !CONFIG_USER_ONLY */

/**
 * CPUDumpFlags:
 * @CPU_DUMP_CODE:
 * @CPU_DUMP_FPU: dump FPU register state, not just integer
 * @CPU_DUMP_CCOP: dump info about TCG QEMU's condition code optimization state
 * @CPU_DUMP_VPU: dump VPU registers
 */
enum CPUDumpFlags {
    CPU_DUMP_CODE = 0x00010000,
    CPU_DUMP_FPU  = 0x00020000,
    CPU_DUMP_CCOP = 0x00040000,
    CPU_DUMP_VPU  = 0x00080000,
};

/**
 * cpu_dump_state:
 * @cpu: The CPU whose state is to be dumped.
 * @f: If non-null, dump to this stream, else to current print sink.
 *
 * Dumps CPU state.
 */
void cpu_dump_state(CPUState *cpu, FILE *f, int flags);

#ifndef CONFIG_USER_ONLY
/**
 * cpu_get_phys_page_attrs_debug:
 * @cpu: The CPU to obtain the physical page address for.
 * @addr: The virtual address.
 * @attrs: Updated on return with the memory transaction attributes to use
 *         for this access.
 *
 * Obtains the physical page corresponding to a virtual one, together
 * with the corresponding memory transaction attributes to use for the access.
 * Use it only for debugging because no protection checks are done.
 *
 * Returns: Corresponding physical page address or -1 if no page found.
 */
hwaddr cpu_get_phys_page_attrs_debug(CPUState *cpu, vaddr addr,
                                     MemTxAttrs *attrs);

/**
 * cpu_get_phys_page_debug:
 * @cpu: The CPU to obtain the physical page address for.
 * @addr: The virtual address.
 *
 * Obtains the physical page corresponding to a virtual one.
 * Use it only for debugging because no protection checks are done.
 *
 * Returns: Corresponding physical page address or -1 if no page found.
 */
hwaddr cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);

/** cpu_asidx_from_attrs:
 * @cpu: CPU
 * @attrs: memory transaction attributes
 *
 * Returns the address space index specifying the CPU AddressSpace
 * to use for a memory access with the given transaction attributes.
 */
int cpu_asidx_from_attrs(CPUState *cpu, MemTxAttrs attrs);

/**
 * cpu_virtio_is_big_endian:
 * @cpu: CPU

 * Returns %true if a CPU which supports runtime configurable endianness
 * is currently big-endian.
 */
bool cpu_virtio_is_big_endian(CPUState *cpu);

/**
 * cpu_has_work:
 * @cpu: The vCPU to check.
 *
 * Checks whether the CPU has work to do.
 *
 * Returns: %true if the CPU has work, %false otherwise.
 */
bool cpu_has_work(CPUState *cpu);

#endif /* CONFIG_USER_ONLY */

/**
 * cpu_list_add:
 * @cpu: The CPU to be added to the list of CPUs.
 */
void cpu_list_add(CPUState *cpu);

/**
 * cpu_list_remove:
 * @cpu: The CPU to be removed from the list of CPUs.
 */
void cpu_list_remove(CPUState *cpu);

/**
 * cpu_reset:
 * @cpu: The CPU whose state is to be reset.
 */
void cpu_reset(CPUState *cpu);

/**
 * cpu_class_by_name:
 * @typename: The CPU base type.
 * @cpu_model: The model string without any parameters.
 *
 * Looks up a concrete CPU #ObjectClass matching name @cpu_model.
 *
 * Returns: A concrete #CPUClass or %NULL if no matching class is found
 *          or if the matching class is abstract.
 */
ObjectClass *cpu_class_by_name(const char *typename, const char *cpu_model);

/**
 * cpu_model_from_type:
 * @typename: The CPU type name
 *
 * Extract the CPU model name from the CPU type name. The
 * CPU type name is either the combination of the CPU model
 * name and suffix, or same to the CPU model name.
 *
 * Returns: CPU model name or NULL if the CPU class doesn't exist
 *          The user should g_free() the string once no longer needed.
 */
char *cpu_model_from_type(const char *typename);

/**
 * cpu_create:
 * @typename: The CPU type.
 *
 * Instantiates a CPU and realizes the CPU.
 *
 * Returns: A #CPUState or %NULL if an error occurred.
 */
CPUState *cpu_create(const char *typename);

/**
 * parse_cpu_option:
 * @cpu_option: The -cpu option including optional parameters.
 *
 * processes optional parameters and registers them as global properties
 *
 * Returns: type of CPU to create or prints error and terminates process
 *          if an error occurred.
 */
const char *parse_cpu_option(const char *cpu_option);

/**
 * qemu_cpu_is_self:
 * @cpu: The vCPU to check against.
 *
 * Checks whether the caller is executing on the vCPU thread.
 *
 * Returns: %true if called from @cpu's thread, %false otherwise.
 */
bool qemu_cpu_is_self(CPUState *cpu);

/**
 * qemu_cpu_kick:
 * @cpu: The vCPU to kick.
 *
 * Kicks @cpu's thread.
 */
void qemu_cpu_kick(CPUState *cpu);

/**
 * cpu_is_stopped:
 * @cpu: The CPU to check.
 *
 * Checks whether the CPU is stopped.
 *
 * Returns: %true if run state is not running or if artificially stopped;
 * %false otherwise.
 */
bool cpu_is_stopped(CPUState *cpu);

/**
 * do_run_on_cpu:
 * @cpu: The vCPU to run on.
 * @func: The function to be executed.
 * @data: Data to pass to the function.
 * @mutex: Mutex to release while waiting for @func to run.
 *
 * Used internally in the implementation of run_on_cpu.
 */
void do_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data,
                   QemuMutex *mutex);

/**
 * run_on_cpu:
 * @cpu: The vCPU to run on.
 * @func: The function to be executed.
 * @data: Data to pass to the function.
 *
 * Schedules the function @func for execution on the vCPU @cpu.
 */
void run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data);

/**
 * async_run_on_cpu:
 * @cpu: The vCPU to run on.
 * @func: The function to be executed.
 * @data: Data to pass to the function.
 *
 * Schedules the function @func for execution on the vCPU @cpu asynchronously.
 */
void async_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data);

/**
 * async_safe_run_on_cpu:
 * @cpu: The vCPU to run on.
 * @func: The function to be executed.
 * @data: Data to pass to the function.
 *
 * Schedules the function @func for execution on the vCPU @cpu asynchronously,
 * while all other vCPUs are sleeping.
 *
 * Unlike run_on_cpu and async_run_on_cpu, the function is run outside the
 * BQL.
 */
void async_safe_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data);

/**
 * cpu_in_exclusive_context()
 * @cpu: The vCPU to check
 *
 * Returns true if @cpu is an exclusive context, for example running
 * something which has previously been queued via async_safe_run_on_cpu().
 */
static inline bool cpu_in_exclusive_context(const CPUState *cpu)
{
    return cpu->exclusive_context_count;
}

/**
 * qemu_get_cpu:
 * @index: The CPUState@cpu_index value of the CPU to obtain.
 *
 * Gets a CPU matching @index.
 *
 * Returns: The CPU or %NULL if there is no matching CPU.
 */
CPUState *qemu_get_cpu(int index);

/**
 * cpu_exists:
 * @id: Guest-exposed CPU ID to lookup.
 *
 * Search for CPU with specified ID.
 *
 * Returns: %true - CPU is found, %false - CPU isn't found.
 */
bool cpu_exists(int64_t id);

/**
 * cpu_by_arch_id:
 * @id: Guest-exposed CPU ID of the CPU to obtain.
 *
 * Get a CPU with matching @id.
 *
 * Returns: The CPU or %NULL if there is no matching CPU.
 */
CPUState *cpu_by_arch_id(int64_t id);

/**
 * cpu_interrupt:
 * @cpu: The CPU to set an interrupt on.
 * @mask: The interrupts to set.
 *
 * Invokes the interrupt handler.
 */

void cpu_interrupt(CPUState *cpu, int mask);

/**
 * cpu_set_pc:
 * @cpu: The CPU to set the program counter for.
 * @addr: Program counter value.
 *
 * Sets the program counter for a CPU.
 */
static inline void cpu_set_pc(CPUState *cpu, vaddr addr)
{
    cpu->cc->set_pc(cpu, addr);
}

/**
 * cpu_reset_interrupt:
 * @cpu: The CPU to clear the interrupt on.
 * @mask: The interrupt mask to clear.
 *
 * Resets interrupts on the vCPU @cpu.
 */
void cpu_reset_interrupt(CPUState *cpu, int mask);

/**
 * cpu_exit:
 * @cpu: The CPU to exit.
 *
 * Requests the CPU @cpu to exit execution.
 */
void cpu_exit(CPUState *cpu);

/**
 * cpu_pause:
 * @cpu: The CPU to pause.
 *
 * Pauses CPU, i.e. puts CPU into stopped state.
 */
void cpu_pause(CPUState *cpu);

/**
 * cpu_resume:
 * @cpu: The CPU to resume.
 *
 * Resumes CPU, i.e. puts CPU into runnable state.
 */
void cpu_resume(CPUState *cpu);

/**
 * cpu_remove_sync:
 * @cpu: The CPU to remove.
 *
 * Requests the CPU to be removed and waits till it is removed.
 */
void cpu_remove_sync(CPUState *cpu);

/**
 * free_queued_cpu_work() - free all items on CPU work queue
 * @cpu: The CPU which work queue to free.
 */
void free_queued_cpu_work(CPUState *cpu);

/**
 * process_queued_cpu_work() - process all items on CPU work queue
 * @cpu: The CPU which work queue to process.
 */
void process_queued_cpu_work(CPUState *cpu);

/**
 * cpu_exec_start:
 * @cpu: The CPU for the current thread.
 *
 * Record that a CPU has started execution and can be interrupted with
 * cpu_exit.
 */
void cpu_exec_start(CPUState *cpu);

/**
 * cpu_exec_end:
 * @cpu: The CPU for the current thread.
 *
 * Record that a CPU has stopped execution and exclusive sections
 * can be executed without interrupting it.
 */
void cpu_exec_end(CPUState *cpu);

/**
 * start_exclusive:
 *
 * Wait for a concurrent exclusive section to end, and then start
 * a section of work that is run while other CPUs are not running
 * between cpu_exec_start and cpu_exec_end.  CPUs that are running
 * cpu_exec are exited immediately.  CPUs that call cpu_exec_start
 * during the exclusive section go to sleep until this CPU calls
 * end_exclusive.
 */
void start_exclusive(void);

/**
 * end_exclusive:
 *
 * Concludes an exclusive execution section started by start_exclusive.
 */
void end_exclusive(void);

/**
 * qemu_init_vcpu:
 * @cpu: The vCPU to initialize.
 *
 * Initializes a vCPU.
 */
void qemu_init_vcpu(CPUState *cpu);

#define SSTEP_ENABLE  0x1  /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2  /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4  /* Do not Timers while single stepping */

/**
 * cpu_single_step:
 * @cpu: CPU to the flags for.
 * @enabled: Flags to enable.
 *
 * Enables or disables single-stepping for @cpu.
 */
void cpu_single_step(CPUState *cpu, int enabled);

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
/* 0x08 currently unused */
#define BP_GDB                0x10
#define BP_CPU                0x20
#define BP_ANY                (BP_GDB | BP_CPU)
#define BP_HIT_SHIFT          6
#define BP_WATCHPOINT_HIT_READ  (BP_MEM_READ << BP_HIT_SHIFT)
#define BP_WATCHPOINT_HIT_WRITE (BP_MEM_WRITE << BP_HIT_SHIFT)
#define BP_WATCHPOINT_HIT       (BP_MEM_ACCESS << BP_HIT_SHIFT)

int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags,
                          CPUBreakpoint **breakpoint);
int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags);
void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint);
void cpu_breakpoint_remove_all(CPUState *cpu, int mask);

/* Return true if PC matches an installed breakpoint.  */
static inline bool cpu_breakpoint_test(CPUState *cpu, vaddr pc, int mask)
{
    CPUBreakpoint *bp;

    if (unlikely(!QTAILQ_EMPTY(&cpu->breakpoints))) {
        QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
            if (bp->pc == pc && (bp->flags & mask)) {
                return true;
            }
        }
    }
    return false;
}

#if defined(CONFIG_USER_ONLY)
static inline int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
                                        int flags, CPUWatchpoint **watchpoint)
{
    return -ENOSYS;
}

static inline int cpu_watchpoint_remove(CPUState *cpu, vaddr addr,
                                        vaddr len, int flags)
{
    return -ENOSYS;
}

static inline void cpu_watchpoint_remove_by_ref(CPUState *cpu,
                                                CPUWatchpoint *wp)
{
}

static inline void cpu_watchpoint_remove_all(CPUState *cpu, int mask)
{
}
#else
int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
                          int flags, CPUWatchpoint **watchpoint);
int cpu_watchpoint_remove(CPUState *cpu, vaddr addr,
                          vaddr len, int flags);
void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint);
void cpu_watchpoint_remove_all(CPUState *cpu, int mask);
#endif

/**
 * cpu_get_address_space:
 * @cpu: CPU to get address space from
 * @asidx: index identifying which address space to get
 *
 * Return the requested address space of this CPU. @asidx
 * specifies which address space to read.
 */
AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx);

G_NORETURN void cpu_abort(CPUState *cpu, const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

/* $(top_srcdir)/cpu.c */
void cpu_class_init_props(DeviceClass *dc);
void cpu_exec_class_post_init(CPUClass *cc);
void cpu_exec_initfn(CPUState *cpu);
void cpu_vmstate_register(CPUState *cpu);
void cpu_vmstate_unregister(CPUState *cpu);
bool cpu_exec_realizefn(CPUState *cpu, Error **errp);
void cpu_exec_unrealizefn(CPUState *cpu);
void cpu_exec_reset_hold(CPUState *cpu);

const char *target_name(void);

#ifdef COMPILING_PER_TARGET

#ifndef CONFIG_USER_ONLY

extern const VMStateDescription vmstate_cpu_common;

#define VMSTATE_CPU() {                                                     \
    .name = "parent_obj",                                                   \
    .size = sizeof(CPUState),                                               \
    .vmsd = &vmstate_cpu_common,                                            \
    .flags = VMS_STRUCT,                                                    \
    .offset = 0,                                                            \
}
#endif /* !CONFIG_USER_ONLY */

#endif /* COMPILING_PER_TARGET */

#define UNASSIGNED_CPU_INDEX -1
#define UNASSIGNED_CLUSTER_INDEX -1

#endif
