/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_QEMU_PLUGIN_H
#define QEMU_QEMU_PLUGIN_H

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * For best performance, build the plugin with -fvisibility=hidden so that
 * QEMU_PLUGIN_LOCAL is implicit. Then, just mark qemu_plugin_install with
 * QEMU_PLUGIN_EXPORT. For more info, see
 *   https://gcc.gnu.org/wiki/Visibility
 */
#if defined _WIN32 || defined __CYGWIN__
  #ifdef CONFIG_PLUGIN
    #define QEMU_PLUGIN_EXPORT __declspec(dllimport)
    #define QEMU_PLUGIN_API __declspec(dllexport)
  #else
    #define QEMU_PLUGIN_EXPORT __declspec(dllexport)
    #define QEMU_PLUGIN_API __declspec(dllimport)
  #endif
  #define QEMU_PLUGIN_LOCAL
#else
  #define QEMU_PLUGIN_EXPORT __attribute__((visibility("default")))
  #define QEMU_PLUGIN_LOCAL  __attribute__((visibility("hidden")))
  #define QEMU_PLUGIN_API
#endif

/**
 * typedef qemu_plugin_id_t - Unique plugin ID
 */
typedef uint64_t qemu_plugin_id_t;

/*
 * Versioning plugins:
 *
 * The plugin API will pass a minimum and current API version that
 * QEMU currently supports. The minimum API will be incremented if an
 * API needs to be deprecated.
 *
 * The plugins export the API they were built against by exposing the
 * symbol qemu_plugin_version which can be checked.
 *
 * version 2:
 * - removed qemu_plugin_n_vcpus and qemu_plugin_n_max_vcpus
 * - Remove qemu_plugin_register_vcpu_{tb, insn, mem}_exec_inline.
 *   Those functions are replaced by *_per_vcpu variants, which guarantee
 *   thread-safety for operations.
 *
 * version 3:
 * - modified arguments and return value of qemu_plugin_insn_data to copy
 *   the data into a user-provided buffer instead of returning a pointer
 *   to the data.
 *
 * version 4:
 * - added qemu_plugin_read_memory_vaddr
 *
 * version 5:
 * - added qemu_plugin_write_register
 * - added qemu_plugin_cpu_state_save, qemu_plugin_cpu_state_restore,
 *   qemu_plugin_cpu_state_free (CPU state snapshot/rollback)
 * - added qemu_plugin_set_pc, qemu_plugin_get_pc (program counter access)
 * - added qemu_plugin_exec_inline_insn (execute one instruction)
 *
 * version 6:
 * - added qemu_plugin_insn_detail (structured Capstone detail for
 *   instruction operands, groups, and implicit registers)
 *
 * version 7:
 * - added qemu_plugin_insn_branch_target_pc (the translator-resolved
 *   static control-transfer target of a branch instruction)
 *
 * version 8:
 * - added qemu_plugin_request_tb_flush (drop the TB cache from a
 *   plugin so a state change that gates translation-time
 *   instrumentation can take effect on every subsequent TB)
 *
 * version 9:
 * - added qemu_plugin_register_asid_write_cb (synchronous notification
 *   at the architectural address-space-register commit points; fires
 *   even while the per-vCPU path-event queue is disabled)
 *
 * version 10:
 * - added qemu_plugin_vaddr_to_paddr (debug-walk the current address
 *   space's translation; physical-page identity for address spaces a
 *   narrow ASID cannot distinguish)
 * - added qemu_plugin_get_thread_ptr (the kernel-maintained per-thread
 *   pointer register; guest-thread identity independent of the vCPU a
 *   thread happens to be scheduled on)
 *
 * version 11:
 * - added qemu_plugin_vaddr_is_kernel (classify a code virtual address's
 *   privilege domain via the target's own MMU / segment logic; a
 *   speculation-proof kernel-vs-user split with no page-table walk)
 *
 * version 12:
 * - added qemu_plugin_register_devio_cb (block-device I/O issue/complete
 *   notifications from the block backend, for disk-request wire records).
 *   The registration also carries a doorbell hook: the guest's virtqueue
 *   notify (kick) executes in vCPU context, so the block backend's later
 *   (main-loop) issue notification is correlated back to the issuing vCPU
 *   through a device token, giving exact owner attribution instead of a
 *   positional guess.
 *
 * version 13:
 * - added qemu_plugin_thread_ptr_tracks_current (whether the target's
 *   thread-pointer register still names the executing software thread
 *   when sampled inside the kernel, so a guest task switch that happens
 *   entirely in kernel code can be followed).
 *
 * version 14:
 * - struct qemu_plugin_cpu_event gained @tp/@tp_ok: the thread pointer
 *   sampled at the event instant, so an ASYNC_ENTER names the thread the
 *   interrupt was DELIVERED in even when that context is gone (or was
 *   never otherwise observable) by the time the event is drained.
 * - qemu_plugin_thread_ptr_tracks_current() became a property of the
 *   sampling context rather than of the target: RISC-V now reports the
 *   kernel's current-task pointer (sscratch/tp per the S-mode trap-entry
 *   swap) and answers true at U/S privilege, false in M-mode firmware
 *   and under H-extension virtualization.
 */

extern QEMU_PLUGIN_EXPORT int qemu_plugin_version;

#define QEMU_PLUGIN_VERSION 14

/**
 * struct qemu_info_t - system information for plugins
 *
 * This structure provides for some limited information about the
 * system to allow the plugin to make decisions on how to proceed. For
 * example it might only be suitable for running on some guest
 * architectures or when under full system emulation.
 */
typedef struct qemu_info_t {
    /** @target_name: string describing architecture */
    const char *target_name;
    /** @version: minimum and current plugin API level */
    struct {
        int min;
        int cur;
    } version;
    /** @system_emulation: is this a full system emulation? */
    bool system_emulation;
    union {
        /** @system: information relevant to system emulation */
        struct {
            /** @system.smp_vcpus: initial number of vCPUs */
            int smp_vcpus;
            /** @system.max_vcpus: maximum possible number of vCPUs */
            int max_vcpus;
        } system;
    };
} qemu_info_t;

/**
 * qemu_plugin_install() - Install a plugin
 * @id: this plugin's opaque ID
 * @info: a block describing some details about the guest
 * @argc: number of arguments
 * @argv: array of arguments (@argc elements)
 *
 * All plugins must export this symbol which is called when the plugin
 * is first loaded. Calling qemu_plugin_uninstall() from this function
 * is a bug.
 *
 * Note: @info is only live during the call. Copy any information we
 * want to keep. @argv remains valid throughout the lifetime of the
 * loaded plugin.
 *
 * Return: 0 on successful loading, !0 for an error.
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv);

/**
 * typedef qemu_plugin_simple_cb_t - simple callback
 * @id: the unique qemu_plugin_id_t
 *
 * This callback passes no information aside from the unique @id.
 */
typedef void (*qemu_plugin_simple_cb_t)(qemu_plugin_id_t id);

/**
 * typedef qemu_plugin_udata_cb_t - callback with user data
 * @id: the unique qemu_plugin_id_t
 * @userdata: a pointer to some user data supplied when the callback
 * was registered.
 */
typedef void (*qemu_plugin_udata_cb_t)(qemu_plugin_id_t id, void *userdata);

/**
 * typedef qemu_plugin_vcpu_simple_cb_t - vcpu callback
 * @id: the unique qemu_plugin_id_t
 * @vcpu_index: the current vcpu context
 */
typedef void (*qemu_plugin_vcpu_simple_cb_t)(qemu_plugin_id_t id,
                                             unsigned int vcpu_index);

/**
 * typedef qemu_plugin_vcpu_udata_cb_t - vcpu callback
 * @vcpu_index: the current vcpu context
 * @userdata: a pointer to some user data supplied when the callback
 * was registered.
 */
typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int vcpu_index,
                                            void *userdata);

/**
 * qemu_plugin_uninstall() - Uninstall a plugin
 * @id: this plugin's opaque ID
 * @cb: callback to be called once the plugin has been removed
 *
 * Do NOT assume that the plugin has been uninstalled once this function
 * returns. Plugins are uninstalled asynchronously, and therefore the given
 * plugin receives callbacks until @cb is called.
 *
 * Note: Calling this function from qemu_plugin_install() is a bug.
 */
QEMU_PLUGIN_API
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb);

/**
 * qemu_plugin_reset() - Reset a plugin
 * @id: this plugin's opaque ID
 * @cb: callback to be called once the plugin has been reset
 *
 * Unregisters all callbacks for the plugin given by @id.
 *
 * Do NOT assume that the plugin has been reset once this function returns.
 * Plugins are reset asynchronously, and therefore the given plugin receives
 * callbacks until @cb is called.
 */
QEMU_PLUGIN_API
void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb);

/**
 * qemu_plugin_register_vcpu_init_cb() - register a vCPU initialization callback
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a vCPU is initialized.
 *
 * See also: qemu_plugin_register_vcpu_exit_cb()
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);

/**
 * qemu_plugin_register_vcpu_exit_cb() - register a vCPU exit callback
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a vCPU exits.
 *
 * See also: qemu_plugin_register_vcpu_init_cb()
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);

/**
 * qemu_plugin_register_vcpu_idle_cb() - register a vCPU idle callback
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a vCPU idles.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_idle_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);

/**
 * qemu_plugin_register_vcpu_resume_cb() - register a vCPU resume callback
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a vCPU resumes execution.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_resume_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_simple_cb_t cb);

/** struct qemu_plugin_tb - Opaque handle for a translation block */
struct qemu_plugin_tb;
/** struct qemu_plugin_insn - Opaque handle for a translated instruction */
struct qemu_plugin_insn;
/** struct qemu_plugin_scoreboard - Opaque handle for a scoreboard */
struct qemu_plugin_scoreboard;

/**
 * typedef qemu_plugin_u64 - uint64_t member of an entry in a scoreboard
 *
 * This field allows to access a specific uint64_t member in one given entry,
 * located at a specified offset. Inline operations expect this as entry.
 */
typedef struct {
    struct qemu_plugin_scoreboard *score;
    size_t offset;
} qemu_plugin_u64;

/**
 * enum qemu_plugin_cb_flags - type of callback
 *
 * @QEMU_PLUGIN_CB_NO_REGS: callback does not access the CPU's regs
 * @QEMU_PLUGIN_CB_R_REGS: callback reads the CPU's regs
 * @QEMU_PLUGIN_CB_RW_REGS: callback reads and writes the CPU's regs
 *
 * QEMU_PLUGIN_CB_RW_REGS enables write_register, cpu_state_restore,
 * set_pc, and exec_inline_insn from within the callback.
 */
enum qemu_plugin_cb_flags {
    QEMU_PLUGIN_CB_NO_REGS,
    QEMU_PLUGIN_CB_R_REGS,
    QEMU_PLUGIN_CB_RW_REGS,
};

enum qemu_plugin_mem_rw {
    QEMU_PLUGIN_MEM_R = 1,
    QEMU_PLUGIN_MEM_W,
    QEMU_PLUGIN_MEM_RW,
};

enum qemu_plugin_mem_value_type {
    QEMU_PLUGIN_MEM_VALUE_U8,
    QEMU_PLUGIN_MEM_VALUE_U16,
    QEMU_PLUGIN_MEM_VALUE_U32,
    QEMU_PLUGIN_MEM_VALUE_U64,
    QEMU_PLUGIN_MEM_VALUE_U128,
    /*
     * The access is wider than the 128 bits qemu_plugin_mem_value can
     * carry (CPUState only ever latches the low 128 bits into
     * plugin_mem_value_low/high — see tcg_gen_plugin_mem_cb() in
     * tcg/tcg-op-ldst.c).  No in-tree target currently emits a MemOp
     * whose size shift exceeds MO_128, so this is a forward-compat
     * degrade path rather than a live case; appended at the end of the
     * enum to avoid renumbering the existing values.  data.u128 is
     * zeroed rather than left uninitialized.
     */
    QEMU_PLUGIN_MEM_VALUE_INVALID,
};

/* typedef qemu_plugin_mem_value - value accessed during a load/store */
typedef struct {
    enum qemu_plugin_mem_value_type type;
    union {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        struct {
            uint64_t low;
            uint64_t high;
        } u128;
    } data;
} qemu_plugin_mem_value;

/**
 * enum qemu_plugin_cond - condition to enable callback
 *
 * @QEMU_PLUGIN_COND_NEVER: false
 * @QEMU_PLUGIN_COND_ALWAYS: true
 * @QEMU_PLUGIN_COND_EQ: is equal?
 * @QEMU_PLUGIN_COND_NE: is not equal?
 * @QEMU_PLUGIN_COND_LT: is less than?
 * @QEMU_PLUGIN_COND_LE: is less than or equal?
 * @QEMU_PLUGIN_COND_GT: is greater than?
 * @QEMU_PLUGIN_COND_GE: is greater than or equal?
 */
enum qemu_plugin_cond {
    QEMU_PLUGIN_COND_NEVER,
    QEMU_PLUGIN_COND_ALWAYS,
    QEMU_PLUGIN_COND_EQ,
    QEMU_PLUGIN_COND_NE,
    QEMU_PLUGIN_COND_LT,
    QEMU_PLUGIN_COND_LE,
    QEMU_PLUGIN_COND_GT,
    QEMU_PLUGIN_COND_GE,
};

/**
 * typedef qemu_plugin_vcpu_tb_trans_cb_t - translation callback
 * @id: unique plugin id
 * @tb: opaque handle used for querying and instrumenting a block.
 */
typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
                                               struct qemu_plugin_tb *tb);

/**
 * qemu_plugin_register_vcpu_tb_trans_cb() - register a translate cb
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a translation occurs. The @cb
 * function is passed an opaque qemu_plugin_type which it can query
 * for additional information including the list of translated
 * instructions. At this point the plugin can register further
 * callbacks to be triggered when the block or individual instruction
 * executes.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb);

/**
 * qemu_plugin_register_vcpu_tb_exec_cb() - register execution callback
 * @tb: the opaque qemu_plugin_tb handle for the translation
 * @cb: callback function
 * @flags: does the plugin read or write the CPU's registers?
 * @userdata: any plugin data to pass to the @cb?
 *
 * The @cb function is called every time a translated unit executes.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *userdata);

/**
 * qemu_plugin_register_vcpu_tb_exec_cond_cb() - register conditional callback
 * @tb: the opaque qemu_plugin_tb handle for the translation
 * @cb: callback function
 * @cond: condition to enable callback
 * @entry: first operand for condition
 * @imm: second operand for condition
 * @flags: does the plugin read or write the CPU's registers?
 * @userdata: any plugin data to pass to the @cb?
 *
 * The @cb function is called when a translated unit executes if
 * entry @cond imm is true.
 * If condition is QEMU_PLUGIN_COND_ALWAYS, condition is never interpreted and
 * this function is equivalent to qemu_plugin_register_vcpu_tb_exec_cb.
 * If condition QEMU_PLUGIN_COND_NEVER, condition is never interpreted and
 * callback is never installed.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_tb_exec_cond_cb(struct qemu_plugin_tb *tb,
                                               qemu_plugin_vcpu_udata_cb_t cb,
                                               enum qemu_plugin_cb_flags flags,
                                               enum qemu_plugin_cond cond,
                                               qemu_plugin_u64 entry,
                                               uint64_t imm,
                                               void *userdata);

/**
 * enum qemu_plugin_op - describes an inline op
 *
 * @QEMU_PLUGIN_INLINE_ADD_U64: add an immediate value uint64_t
 * @QEMU_PLUGIN_INLINE_STORE_U64: store an immediate value uint64_t
 */

enum qemu_plugin_op {
    QEMU_PLUGIN_INLINE_ADD_U64,
    QEMU_PLUGIN_INLINE_STORE_U64,
};

/**
 * qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu() - execution inline op
 * @tb: the opaque qemu_plugin_tb handle for the translation
 * @op: the type of qemu_plugin_op (e.g. ADD_U64)
 * @entry: entry to run op
 * @imm: the op data (e.g. 1)
 *
 * Insert an inline op on a given scoreboard entry.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
    struct qemu_plugin_tb *tb,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm);

/**
 * qemu_plugin_register_vcpu_insn_exec_cb() - register insn execution cb
 * @insn: the opaque qemu_plugin_insn handle for an instruction
 * @cb: callback function
 * @flags: does the plugin read or write the CPU's registers?
 * @userdata: any plugin data to pass to the @cb?
 *
 * The @cb function is called every time an instruction is executed
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *userdata);

/**
 * qemu_plugin_register_vcpu_insn_exec_cond_cb() - conditional insn execution cb
 * @insn: the opaque qemu_plugin_insn handle for an instruction
 * @cb: callback function
 * @flags: does the plugin read or write the CPU's registers?
 * @cond: condition to enable callback
 * @entry: first operand for condition
 * @imm: second operand for condition
 * @userdata: any plugin data to pass to the @cb?
 *
 * The @cb function is called when an instruction executes if
 * entry @cond imm is true.
 * If condition is QEMU_PLUGIN_COND_ALWAYS, condition is never interpreted and
 * this function is equivalent to qemu_plugin_register_vcpu_insn_exec_cb.
 * If condition QEMU_PLUGIN_COND_NEVER, condition is never interpreted and
 * callback is never installed.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_insn_exec_cond_cb(
    struct qemu_plugin_insn *insn,
    qemu_plugin_vcpu_udata_cb_t cb,
    enum qemu_plugin_cb_flags flags,
    enum qemu_plugin_cond cond,
    qemu_plugin_u64 entry,
    uint64_t imm,
    void *userdata);

/**
 * qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu() - insn exec inline op
 * @insn: the opaque qemu_plugin_insn handle for an instruction
 * @op: the type of qemu_plugin_op (e.g. ADD_U64)
 * @entry: entry to run op
 * @imm: the op data (e.g. 1)
 *
 * Insert an inline op to every time an instruction executes.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
    struct qemu_plugin_insn *insn,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm);

/**
 * qemu_plugin_tb_n_insns() - query helper for number of insns in TB
 * @tb: opaque handle to TB passed to callback
 *
 * Returns: number of instructions in this block
 */
QEMU_PLUGIN_API
size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb);

/**
 * qemu_plugin_tb_vaddr() - query helper for vaddr of TB start
 * @tb: opaque handle to TB passed to callback
 *
 * Returns: virtual address of block start
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb);

/**
 * qemu_plugin_tb_get_insn() - retrieve handle for instruction
 * @tb: opaque handle to TB passed to callback
 * @idx: instruction number, 0 indexed
 *
 * The returned handle can be used in follow up helper queries as well
 * as when instrumenting an instruction. It is only valid for the
 * lifetime of the callback.
 *
 * Returns: opaque handle to instruction
 */
QEMU_PLUGIN_API
struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx);

/**
 * qemu_plugin_insn_data() - copy instruction data
 * @insn: opaque instruction handle from qemu_plugin_tb_get_insn()
 * @dest: destination into which data is copied
 * @len: length of dest
 *
 * Returns the number of bytes copied, minimum of @len and insn size.
 */
QEMU_PLUGIN_API
size_t qemu_plugin_insn_data(const struct qemu_plugin_insn *insn,
                             void *dest, size_t len);

/**
 * qemu_plugin_insn_size() - return size of instruction
 * @insn: opaque instruction handle from qemu_plugin_tb_get_insn()
 *
 * Returns: size of instruction in bytes
 */
QEMU_PLUGIN_API
size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn);

/**
 * qemu_plugin_insn_vaddr() - return vaddr of instruction
 * @insn: opaque instruction handle from qemu_plugin_tb_get_insn()
 *
 * Returns: virtual address of instruction
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn);

/**
 * qemu_plugin_insn_haddr() - return hardware addr of instruction
 * @insn: opaque instruction handle from qemu_plugin_tb_get_insn()
 *
 * Returns: hardware (physical) target address of instruction
 */
QEMU_PLUGIN_API
void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn);

/**
 * qemu_plugin_insn_branch_target_pc() - resolved static branch target
 * @insn: opaque instruction handle from qemu_plugin_tb_get_insn()
 *
 * Returns the static control-transfer target the per-ISA translator
 * resolved for this instruction during translation — the same value
 * fed to gen_goto_tb / equivalents.  Returns 0 when no static target
 * exists: either the instruction is not a control transfer, or it is
 * an indirect / register-form branch whose target is only known at
 * runtime (plugins should fall back to their own observed-target
 * history for those).
 *
 * Wrong-path tracers should consume this rather than re-decoding the
 * branch immediate themselves — per-ISA encoding (PC-relative vs.
 * absolute, sign extension, MIPS delay-slot accounting, ARM Thumb
 * interworking) is already correctly resolved by the translator.
 *
 * Returns: target PC, or 0 if no static target.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_insn_branch_target_pc(const struct qemu_plugin_insn *insn);

/**
 * typedef qemu_plugin_meminfo_t - opaque memory transaction handle
 *
 * This can be further queried using the qemu_plugin_mem_* query
 * functions.
 */
typedef uint32_t qemu_plugin_meminfo_t;
/** struct qemu_plugin_hwaddr - opaque hw address handle */
struct qemu_plugin_hwaddr;

/**
 * qemu_plugin_mem_size_shift() - get size of access
 * @info: opaque memory transaction handle
 *
 * Returns: size of access in ^2 (0=byte, 1=16bit, 2=32bit etc...)
 */
QEMU_PLUGIN_API
unsigned int qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info);
/**
 * qemu_plugin_mem_is_sign_extended() - was the access sign extended
 * @info: opaque memory transaction handle
 *
 * Returns: true if it was, otherwise false
 */
QEMU_PLUGIN_API
bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info);
/**
 * qemu_plugin_mem_is_big_endian() - was the access big endian
 * @info: opaque memory transaction handle
 *
 * Returns: true if it was, otherwise false
 */
QEMU_PLUGIN_API
bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info);
/**
 * qemu_plugin_mem_is_store() - was the access a store
 * @info: opaque memory transaction handle
 *
 * Returns: true if it was, otherwise false
 */
QEMU_PLUGIN_API
bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info);

/**
 * qemu_plugin_mem_get_value() - return last value loaded/stored
 * @info: opaque memory transaction handle
 *
 * Returns: memory value. If the access is wider than 128 bits — which no
 * in-tree target currently emits, since CPUState only latches the low 128
 * bits of an access for plugin use — the returned value has type
 * QEMU_PLUGIN_MEM_VALUE_INVALID and zeroed data, rather than aborting.
 */
QEMU_PLUGIN_API
qemu_plugin_mem_value qemu_plugin_mem_get_value(qemu_plugin_meminfo_t info);

/**
 * qemu_plugin_get_hwaddr() - return handle for memory operation
 * @info: opaque memory info structure
 * @vaddr: the virtual address of the memory operation
 *
 * For system emulation returns a qemu_plugin_hwaddr handle to query
 * details about the actual physical address backing the virtual
 * address. For linux-user guests it just returns NULL.
 *
 * This handle is *only* valid for the duration of the callback. Any
 * information about the handle should be recovered before the
 * callback returns.
 */
QEMU_PLUGIN_API
struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr);

/*
 * The following additional queries can be run on the hwaddr structure to
 * return information about it - namely whether it is for an IO access and the
 * physical address associated with the access.
 */

/**
 * qemu_plugin_hwaddr_is_io() - query whether memory operation is IO
 * @haddr: address handle from qemu_plugin_get_hwaddr()
 *
 * Returns true if the handle's memory operation is to memory-mapped IO, or
 * false if it is to RAM
 */
QEMU_PLUGIN_API
bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr);

/**
 * qemu_plugin_hwaddr_phys_addr() - query physical address for memory operation
 * @haddr: address handle from qemu_plugin_get_hwaddr()
 *
 * Returns the physical address associated with the memory operation
 *
 * Note that the returned physical address may not be unique if you are dealing
 * with multiple address spaces.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr);

/*
 * Returns a string representing the device. The string is valid for
 * the lifetime of the plugin.
 */
QEMU_PLUGIN_API
const char *qemu_plugin_hwaddr_device_name(const struct qemu_plugin_hwaddr *h);

/**
 * typedef qemu_plugin_vcpu_mem_cb_t - memory callback function type
 * @vcpu_index: the executing vCPU
 * @info: an opaque handle for further queries about the memory
 * @vaddr: the virtual address of the transaction
 * @userdata: any user data attached to the callback
 */
typedef void (*qemu_plugin_vcpu_mem_cb_t) (unsigned int vcpu_index,
                                           qemu_plugin_meminfo_t info,
                                           uint64_t vaddr,
                                           void *userdata);

/**
 * qemu_plugin_register_vcpu_mem_cb() - register memory access callback
 * @insn: handle for instruction to instrument
 * @cb: callback of type qemu_plugin_vcpu_mem_cb_t
 * @flags: (currently unused) callback flags
 * @rw: monitor reads, writes or both
 * @userdata: opaque pointer for userdata
 *
 * This registers a full callback for every memory access generated by
 * an instruction. If the instruction doesn't access memory no
 * callback will be made.
 *
 * The callback reports the vCPU the access took place on, the virtual
 * address of the access and a handle for further queries. The user
 * can attach some userdata to the callback for additional purposes.
 *
 * Other execution threads will continue to execute during the
 * callback so the plugin is responsible for ensuring it doesn't get
 * confused by making appropriate use of locking if required.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *userdata);

/**
 * qemu_plugin_register_vcpu_mem_inline_per_vcpu() - inline op for mem access
 * @insn: handle for instruction to instrument
 * @rw: apply to reads, writes or both
 * @op: the op, of type qemu_plugin_op
 * @entry: entry to run op
 * @imm: immediate data for @op
 *
 * This registers a inline op every memory access generated by the
 * instruction.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_mem_inline_per_vcpu(
    struct qemu_plugin_insn *insn,
    enum qemu_plugin_mem_rw rw,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm);

/**
 * qemu_plugin_request_time_control() - request the ability to control time
 *
 * This grants the plugin the ability to control system time. Only one
 * plugin can control time so if multiple plugins request the ability
 * all but the first will fail.
 *
 * Returns an opaque handle or NULL if fails
 */
QEMU_PLUGIN_API
const void *qemu_plugin_request_time_control(void);

/**
 * qemu_plugin_update_ns() - update system emulation time
 * @handle: opaque handle returned by qemu_plugin_request_time_control()
 * @time: time in nanoseconds
 *
 * This allows an appropriately authorised plugin (i.e. holding the
 * time control handle) to move system time forward to @time. For
 * user-mode emulation the time is not changed by this as all reported
 * time comes from the host kernel.
 *
 * Start time is 0.
 */
QEMU_PLUGIN_API
void qemu_plugin_update_ns(const void *handle, int64_t time);

typedef void
(*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                 int64_t num, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5,
                                 uint64_t a6, uint64_t a7, uint64_t a8);

QEMU_PLUGIN_API
void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb);

typedef void
(*qemu_plugin_vcpu_syscall_ret_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_idx,
                                     int64_t num, int64_t ret);

QEMU_PLUGIN_API
void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb);


/**
 * qemu_plugin_insn_disas() - return disassembly string for instruction
 * @insn: instruction reference
 *
 * Returns an allocated string containing the disassembly
 */

QEMU_PLUGIN_API
char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn);

/*
 * Structured instruction detail from Capstone.
 *
 * Provides operand types, access modes, implicit registers, and
 * instruction group classification without string parsing.
 * Register names are ISA-native Capstone register name strings.
 */

#define QEMU_PLUGIN_INSN_DETAIL_MAX_OPS    16
/*
 * The implicit register lists are copied out of Capstone's
 * regs_read[] / regs_write[] under a MIN() against this cap, so a cap
 * below what any instruction reports does not fail -- it silently
 * deletes architectural registers from the dependency model.  It was 12,
 * and the x86 VZEROUPPER / VZEROALL pair reports sixteen YMM destination
 * writes; the last four were being dropped on 1.26% of the dynamic
 * instructions in the reference x86 traces.  Sixteen is the widest
 * implicit list either decoder produces for any encoding the sweeps
 * reach on the four supported ISAs, so this is a ceiling and not a
 * sample -- if that stops being true, isaxcheck's register comparison is
 * what says so.
 */
#define QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS  16
#define QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ 12
#define QEMU_PLUGIN_INSN_DETAIL_MNEMSZ     32
#define QEMU_PLUGIN_INSN_DETAIL_OPSTRSZ    160

/* Operand types (matching Capstone cs_op_type) */
#define QEMU_PLUGIN_OP_INVALID 0
#define QEMU_PLUGIN_OP_REG     1
#define QEMU_PLUGIN_OP_IMM     2
#define QEMU_PLUGIN_OP_MEM     3
/*
 * A system / control register named by the encoding but living outside
 * the ISA's ordinary register file: an AArch64 MRS/MSR system register,
 * a RISC-V Zicsr CSR, and their kin.
 *
 * These get an operand type of their own because Capstone cannot name
 * them as registers.  It numbers them in spaces of their own
 * (aarch64_sysreg, cs_riscv_op.csr) disjoint from the register enum
 * reg_id otherwise carries, and its register enum has ids for almost
 * none of them: of the 1214 entries in Capstone 6.0.0-Alpha7's
 * aarch64_sysreg, exactly two -- NZCV and FPCR -- have a same-named
 * aarch64_reg, and TPIDR_EL0, FPSR and every EL1 control register have
 * none.  So there is no register id to hand over, and a consumer given
 * the raw encoding would have to carry a per-ISA table to make sense
 * of it.
 *
 * sysreg_class therefore carries the ARCHITECTURAL ROLE, resolved at
 * the Capstone boundary where the rest of the per-instruction register
 * knowledge already lives (see disas/capstone.c).  It is what a
 * consumer maps from; see QEMU_PLUGIN_SYSREG_* below.
 *
 * reg_id holds the raw architectural encoding for identification and
 * reporting -- the aarch64_sysreg value, i.e. the packed
 * op0:op1:CRn:CRm:op2 field (NZCV = 0xda10, TPIDR_EL0 = 0xde82), or
 * the 12-bit RISC-V CSR number (fflags = 0x001, vl = 0xc20).  It is
 * deliberately NOT a Capstone register id and must not be looked up in
 * one.  reg_name carries the printed name where the disassembler
 * supplies one.
 *
 * access is filled from the direction the instruction form implies
 * (MRS reads, MSR writes, Zicsr per its rd/rs1 suppression rules)
 * because Capstone leaves the AArch64 system operand's access bits
 * empty.
 *
 * A plugin that does not model system registers can ignore this type
 * exactly as it ignores QEMU_PLUGIN_OP_INVALID.
 */
#define QEMU_PLUGIN_OP_SYSREG  4

/*
 * Architectural role of a QEMU_PLUGIN_OP_SYSREG operand.
 *
 * The vocabulary is deliberately tiny and names ROLES, not registers:
 * a dependency model schedules against the role, and the specific
 * register is already in reg_id / reg_name for anything that needs it.
 * Every value but OTHER exists because folding that role into OTHER
 * would put a hot, narrow dependency into the same slot as the whole
 * identification / trap / debug register space -- an edge onto
 * whichever system register the last MRS happened to touch.
 *
 * QEMU_PLUGIN_SYSREG_OTHER is the default and the long tail; it is
 * also what an operand carries when the boundary has no opinion, so a
 * zeroed operand reads as "some system register" rather than as a
 * specific one.
 */
#define QEMU_PLUGIN_SYSREG_OTHER     0  /* the long tail: ID, trap,
                                         * translation, counter, debug */
#define QEMU_PLUGIN_SYSREG_FLAGS     1  /* condition flags (AArch64 NZCV) */
#define QEMU_PLUGIN_SYSREG_FPCTRL    2  /* FP / fixed-point rounding-mode
                                         * and status word (FPCR, FPSR,
                                         * fcsr, frm, vxrm, ...) */
#define QEMU_PLUGIN_SYSREG_VECCTRL   3  /* vector configuration (vl,
                                         * vtype, vstart) */
#define QEMU_PLUGIN_SYSREG_THREADPTR 4  /* userspace thread pointer
                                         * (TPIDR_EL0, TPIDRRO_EL0) */

/* Operand access mode (bitmask) */
#define QEMU_PLUGIN_OP_ACC_READ  1
#define QEMU_PLUGIN_OP_ACC_WRITE 2

/* Instruction group flags (bitmask) */
#define QEMU_PLUGIN_GRP_JUMP       (1u << 0)
#define QEMU_PLUGIN_GRP_CALL       (1u << 1)
#define QEMU_PLUGIN_GRP_RET        (1u << 2)
#define QEMU_PLUGIN_GRP_INT        (1u << 3)
#define QEMU_PLUGIN_GRP_IRET       (1u << 4)
#define QEMU_PLUGIN_GRP_PRIVILEGE  (1u << 5)
#define QEMU_PLUGIN_GRP_BRANCH_REL (1u << 6)

typedef struct qemu_plugin_operand {
    uint8_t  type;     /* QEMU_PLUGIN_OP_* */
    uint8_t  access;   /* bitmask of QEMU_PLUGIN_OP_ACC_*, 0 if unknown */
    uint8_t  size;     /* operand size in bytes */
    /*
     * Per-operand vector lane width in bytes.  Plugin-internal
     * metadata derived from Capstone's per-ISA structured detail:
     *   AArch64: decoded from the operand's vector arrangement
     *            specifier (vas) — .4S = 4, .2D = 8, .8H = 2, etc.
     *   x86    : derived from the canonical insn mnemonic suffix
     *            (PS = 4, PD = 8, B = 1, W = 2, D = 4, Q = 8).
     *   RISC-V : the V-extension SEW is a runtime CSR and isn't
     *            derivable from disassembly alone — left at 0.
     *
     * Plugins use this for tracer-side bookkeeping such as mapping
     * vector memops to the dst-reg lanes they fill, or computing the
     * baseline lane bitmap for a refiner.  This field is NOT part
     * of any externally visible trace format — the wire encoding of
     * lane participation is left to higher layers (the champsim
     * tracer surfaces it via dynamic FID deltas).  Zero means
     * "scalar / not derivable for this ISA"; consumers that don't
     * need it can ignore it.
     */
    uint8_t  lane_bytes;
    /*
     * x86 SIB scale: 1, 2, 4, or 8 when an index register participates;
     * 0 or 1 means "no index scaling" (treat as effective scale 1).
     * Always 1 for non-x86 ISAs.  Plugins that compute an effective
     * address from the operand should use:
     *     ea = base + index * (scale ? scale : 1) + disp
     */
    uint8_t  scale;
    uint16_t reg_id;   /* Capstone register ID for reg_name (0 = none) */
    uint16_t index_id; /* Capstone register ID for index_name (0 = none) */
    /*
     * x86 segment-override register on a MEM operand: the Capstone
     * register ID of the segment whose base participates in the
     * effective address (X86_REG_FS / X86_REG_GS / ...), or 0 when the
     * access uses the default segment.  Zero for every non-MEM operand
     * and for every non-x86 ISA (no other supported ISA has segmented
     * addressing).
     *
     * The segment register is a genuine ADDRESS INPUT: the linear
     * address is seg.base + base + index * scale + disp, so an
     * instruction like `mov %fs:0x28, %rax` reads fs.  Capstone only
     * exposes it here -- x86 segment overrides do NOT appear in the
     * implicit regs_read[] list -- so a plugin that walks operands
     * alone would silently drop the dependency (TLS and stack-protector
     * accesses would look input-less).  Plugins attributing address
     * dependencies should add this to the memop's source set alongside
     * reg_id and index_id.
     */
    uint16_t segment_id;
    int64_t  imm;      /* IMM value, or MEM displacement */
    /*
     * AArch64 register-form addressing modifier.  shift_type matches
     * Capstone's arm64_shifter enum (0 = none, ARM64_SFT_LSL,
     * ARM64_SFT_LSR, ARM64_SFT_ASR, ARM64_SFT_ROR, ARM64_SFT_MSL).
     * shift_amount is the shift count in bits.  Always zero for
     * non-AArch64 ISAs and for unshifted operands.  Plugins computing
     * an EA from a register-form load/store should apply the shift to
     * the index register before adding the base.
     */
    uint8_t  shift_type;
    uint8_t  shift_amount;
    /*
     * QEMU_PLUGIN_SYSREG_* — the architectural role of a
     * QEMU_PLUGIN_OP_SYSREG operand.  Zero (OTHER) on every other
     * operand type, which is also its meaning there: no system
     * register is named, so no role is claimed.
     */
    uint8_t  sysreg_class;
    /* REG name (or MEM base register name); empty string if none */
    char     reg_name[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
    /* MEM index register name; empty string if none or not MEM */
    char     index_name[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
} qemu_plugin_operand;

typedef struct qemu_plugin_insn_info {
    uint32_t insn_id;     /* Capstone instruction ID (X86_INS_*, ARM64_INS_*) */
    uint16_t groups;      /* bitmask of QEMU_PLUGIN_GRP_* */
    uint8_t  n_operands;
    uint8_t  n_regs_read;
    uint8_t  n_regs_write;
    bool     has_lock;    /* x86 LOCK prefix detected */
    bool     has_rep;     /* x86 REP/REPNZ prefix detected */
    uint8_t  insn_size;   /* decoded instruction length in bytes (Capstone) */
    char     mnemonic[QEMU_PLUGIN_INSN_DETAIL_MNEMSZ];
    char     op_str[QEMU_PLUGIN_INSN_DETAIL_OPSTRSZ];
    qemu_plugin_operand operands[QEMU_PLUGIN_INSN_DETAIL_MAX_OPS];
    char     regs_read[QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS]
                       [QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
    char     regs_write[QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS]
                        [QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
    uint16_t regs_read_id[QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS];
    uint16_t regs_write_id[QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS];
} qemu_plugin_insn_info;

/**
 * qemu_plugin_insn_detail() - get structured instruction details
 * @insn: opaque instruction handle from qemu_plugin_tb_get_insn()
 * @info: output structure filled with Capstone detail fields
 *
 * Decodes the instruction using Capstone with detail mode enabled
 * and fills @info with operand types, access modes, implicit register
 * names, instruction groups, and prefix information.
 *
 * Register names are ISA-native strings from Capstone (e.g. "rax",
 * "xmm0" for x86; "x0", "sp" for AArch64).
 *
 * Returns true on success, false if Capstone is unavailable or the
 * instruction could not be decoded.
 */
QEMU_PLUGIN_API
bool qemu_plugin_insn_detail(const struct qemu_plugin_insn *insn,
                             qemu_plugin_insn_info *info);

/**
 * qemu_plugin_cap_decode() - decode raw instruction bytes via Capstone
 * @cap_arch: Capstone architecture — pass a Capstone ``cs_arch`` enum value
 *            (e.g. CS_ARCH_X86, CS_ARCH_AARCH64, CS_ARCH_RISCV, CS_ARCH_MIPS).
 * @cap_mode: Capstone mode flags — pass a bitmask of Capstone ``cs_mode``
 *            enum values (e.g. CS_MODE_64, CS_MODE_RISCV64 | CS_MODE_RISCV_C).
 * @data: pointer to raw instruction bytes
 * @size: number of bytes available at @data
 * @pc: virtual address of the instruction
 * @info: output structure filled with Capstone detail fields
 *
 * Opens a standalone Capstone handle with the requested architecture
 * and mode, enables detail mode, and decodes the first instruction
 * from @data.  Unlike qemu_plugin_insn_detail(), this function does
 * not depend on QEMU's per-target disassembler — it works for any
 * ISA that Capstone supports, given the correct arch/mode.
 *
 * The @cap_arch and @cap_mode arguments are forwarded verbatim to
 * cs_open(), so plugins should include <capstone/capstone.h> and
 * use the canonical Capstone enum values rather than shadow constants.
 * This insulates plugins from any future renumbering inside Capstone.
 *
 * x86 automatically uses AT&T syntax.
 *
 * Returns true on success, false if Capstone cannot open or decode.
 */
QEMU_PLUGIN_API
bool qemu_plugin_cap_decode(int cap_arch, unsigned int cap_mode,
                            const uint8_t *data, size_t size,
                            uint64_t pc, qemu_plugin_insn_info *info);

/**
 * qemu_plugin_insn_symbol() - best effort symbol lookup
 * @insn: instruction reference
 *
 * Return a static string referring to the symbol. This is dependent
 * on the binary QEMU is running having provided a symbol table.
 */
QEMU_PLUGIN_API
const char *qemu_plugin_insn_symbol(const struct qemu_plugin_insn *insn);

/**
 * qemu_plugin_vcpu_for_each() - iterate over the existing vCPU
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called once for each existing vCPU.
 *
 * See also: qemu_plugin_register_vcpu_init_cb()
 */
QEMU_PLUGIN_API
void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_simple_cb_t cb);

QEMU_PLUGIN_API
void qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                                   qemu_plugin_simple_cb_t cb);

/**
 * qemu_plugin_request_tb_flush() - drop every cached translation
 *
 * Asks QEMU to invalidate its entire TB cache so subsequent
 * executions retranslate every basic block from scratch and re-fire
 * the plugin's translation callback for each.  Use this when the
 * plugin's translation-time instrumentation depends on dynamic state
 * (for example whether a trace segment is active): toggling that
 * state mid-execution otherwise leaves cached TBs running with their
 * out-of-date instrumentation until QEMU happens to evict them.
 *
 * Runs on the calling vCPU and is async-safe relative to TB
 * execution — any registered flush callback fires before the next TB
 * begins executing.
 */
QEMU_PLUGIN_API
void qemu_plugin_request_tb_flush(void);

/**
 * typedef qemu_plugin_asid_write_cb_t - address-space-register write hook
 * @vcpu_index: the vCPU that committed the write
 * @new_asid: the just-committed value, as reported by
 *            qemu_plugin_get_addr_space_id()
 */
typedef void (*qemu_plugin_asid_write_cb_t)(unsigned int vcpu_index,
                                            uint64_t new_asid);

/**
 * qemu_plugin_register_asid_write_cb() - register ASID-write hook
 * @id: plugin ID
 * @cb: callback, or NULL to unregister
 *
 * Fires synchronously on the owning vCPU thread each time the guest
 * commits a changed value to the register
 * qemu_plugin_get_addr_space_id() reports (the same per-target commit
 * points that produce QEMU_PLUGIN_CPU_EVENT_ASID_WRITE path events),
 * system emulation only.  Unlike the queued event, the hook fires even
 * while the per-vCPU event queue is disabled — a plugin can track
 * address-space transitions during phases where nothing drains the
 * queue.  Wrong-path (speculative) writes are suppressed.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_asid_write_cb(qemu_plugin_id_t id,
                                        qemu_plugin_asid_write_cb_t cb);

/**
 * enum qemu_plugin_devio_dir - direction/kind of a block-device request
 * @QEMU_PLUGIN_DEVIO_READ: data read from the device into guest memory
 * @QEMU_PLUGIN_DEVIO_WRITE: data written from guest memory to the device
 *                           (also pwrite-zeroes / discard — a zero-byte
 *                           payload distinguishes those from a data write)
 * @QEMU_PLUGIN_DEVIO_FLUSH: a cache-flush / write-barrier (no data)
 */
enum qemu_plugin_devio_dir {
    QEMU_PLUGIN_DEVIO_READ  = 0,
    QEMU_PLUGIN_DEVIO_WRITE = 1,
    QEMU_PLUGIN_DEVIO_FLUSH = 2,
};

/**
 * typedef qemu_plugin_devio_doorbell_cb_t - virtqueue-notify (kick) hook
 * @vcpu_index: the vCPU that rang the doorbell (wrote the virtqueue
 *              notify register), resolved from current_cpu, or -1 if the
 *              notify was not raised from a vCPU thread
 * @dev_token: an opaque per-device identity (the block device's
 *             DeviceState pointer, as an integer) that a later start
 *             hook can match to correlate this doorbell with the
 *             asynchronous requests it produced
 *
 * Fires synchronously in vCPU context when the guest kicks a
 * block-device virtqueue, BEFORE the (possibly deferred, main-loop)
 * request processing runs.  It is the one point where the issuing vCPU
 * — and thus the plugin's owning process/thread — is known.  The plugin
 * captures the owner keyed by @dev_token; the start hook, which fires on
 * the main loop with the request geometry but no vCPU, pops the matching
 * doorbell to attribute the request exactly.  System emulation only;
 * correct path only (a spec-mode doorbell store reaches no device).
 */
typedef void (*qemu_plugin_devio_doorbell_cb_t)(int vcpu_index,
                                                uint64_t dev_token);

/**
 * typedef qemu_plugin_devio_start_cb_t - block-device request issue hook
 * @vcpu_index: the vCPU that issued the request when the block layer was
 *              entered synchronously on a vCPU thread, else -1 (the
 *              canonical no-iothread virtio-blk path defers to the main
 *              loop, so this is typically -1 — use @dev_token + the
 *              doorbell hook for the true issuing vCPU)
 * @dir: an enum qemu_plugin_devio_dir value
 * @offset: byte offset of the request within the backing image
 * @bytes: request length in bytes (0 for flush)
 * @dev_token: the attached device's identity (DeviceState pointer as an
 *             integer), matching the doorbell hook's token for a device
 *             whose kick was seen in vCPU context; 0 when no device is
 *             attached.  The plugin correlates this against its captured
 *             doorbells for exact owner attribution, falling back to
 *             positional attribution when no doorbell matches (non-virtio
 *             or kernel-internal I/O).
 *
 * Fires synchronously from the block backend when an asynchronous
 * request (blk_aio_*) is issued.  Returns a nonzero request id the
 * plugin assigns for later correlation with the completion hook; a
 * return of 0 means "not tracked" and suppresses the paired completion
 * notification.  System emulation only.  Never fires on the wrong
 * (speculative) path — a spec-mode doorbell store is sandboxed and
 * reaches no device model.
 */
typedef uint64_t (*qemu_plugin_devio_start_cb_t)(int vcpu_index,
                                                 int dir,
                                                 uint64_t offset,
                                                 uint64_t bytes,
                                                 uint64_t dev_token);

/**
 * typedef qemu_plugin_devio_stop_cb_t - block-device completion hook
 * @request_id: the id a prior start hook returned for this request
 *
 * Fires when a request the start hook tracked (returned nonzero for)
 * completes, from the block backend's completion chokepoint.  In the
 * canonical no-iothread configuration this runs on the main loop
 * thread, not the issuing vCPU thread, so the plugin must serialise
 * its own state.
 */
typedef void (*qemu_plugin_devio_stop_cb_t)(uint64_t request_id);

/**
 * qemu_plugin_register_devio_cb() - register block-device I/O hooks
 * @id: plugin ID
 * @doorbell_cb: virtqueue-notify (kick) hook, or NULL
 * @start_cb: issue hook, or NULL
 * @stop_cb: completion hook, or NULL
 *
 * Registers synchronous notification of block-device virtqueue kicks
 * (in vCPU context) and of request issue / completion at the block
 * backend's blk_aio_* chokepoints (on whichever thread the block layer
 * runs).  System emulation only.  A tracer uses these to place
 * disk-request records in the body stream attributed to the exact
 * issuing process/thread: the doorbell hook captures the owner in vCPU
 * context, the issue hook correlates the request to it by device token,
 * and the completion hook marks where the request finishes.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_devio_cb(qemu_plugin_id_t id,
                                   qemu_plugin_devio_doorbell_cb_t doorbell_cb,
                                   qemu_plugin_devio_start_cb_t start_cb,
                                   qemu_plugin_devio_stop_cb_t stop_cb);

/**
 * qemu_plugin_register_atexit_cb() - register exit callback
 * @id: plugin ID
 * @cb: callback
 * @userdata: user data for callback
 *
 * The @cb function is called once execution has finished. Plugins
 * should be able to free all their resources at this point much like
 * after a reset/uninstall callback is called.
 *
 * In user-mode it is possible a few un-instrumented instructions from
 * child threads may run before the host kernel reaps the threads.
 */
QEMU_PLUGIN_API
void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
                                    qemu_plugin_udata_cb_t cb, void *userdata);

/* returns how many vcpus were started at this point */
QEMU_PLUGIN_API
int qemu_plugin_num_vcpus(void);

/**
 * qemu_plugin_outs() - output string via QEMU's logging system
 * @string: a string
 */
QEMU_PLUGIN_API
void qemu_plugin_outs(const char *string);

/**
 * qemu_plugin_bool_parse() - parses a boolean argument in the form of
 * "<argname>=[on|yes|true|off|no|false]"
 *
 * @name: argument name, the part before the equals sign
 * @val: argument value, what's after the equals sign
 * @ret: output return value
 *
 * returns true if the combination @name=@val parses correctly to a boolean
 * argument, and false otherwise
 */
QEMU_PLUGIN_API
bool qemu_plugin_bool_parse(const char *name, const char *val, bool *ret);

/**
 * qemu_plugin_path_to_binary() - path to binary file being executed
 *
 * Return a string representing the path to the binary. For user-mode
 * this is the main executable. For system emulation we currently
 * return NULL. The user should g_free() the string once no longer
 * needed.
 */
QEMU_PLUGIN_API
const char *qemu_plugin_path_to_binary(void);

/**
 * qemu_plugin_start_code() - returns start of text segment
 *
 * Returns the nominal start address of the main text segment in
 * user-mode. Currently returns 0 for system emulation.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_start_code(void);

/**
 * qemu_plugin_end_code() - returns end of text segment
 *
 * Returns the nominal end address of the main text segment in
 * user-mode. Currently returns 0 for system emulation.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_end_code(void);

/**
 * qemu_plugin_entry_code() - returns start address for module
 *
 * Returns the nominal entry address of the main text segment in
 * user-mode. Currently returns 0 for system emulation.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_entry_code(void);

/** struct qemu_plugin_register - Opaque handle for register access */
struct qemu_plugin_register;

/**
 * typedef qemu_plugin_reg_descriptor - register descriptions
 *
 * @handle: opaque handle for retrieving value with qemu_plugin_read_register
 * @name: register name
 * @feature: optional feature descriptor, can be NULL
 */
typedef struct {
    struct qemu_plugin_register *handle;
    const char *name;
    const char *feature;
} qemu_plugin_reg_descriptor;

/**
 * qemu_plugin_get_registers() - return register list for current vCPU
 *
 * Returns a potentially empty GArray of qemu_plugin_reg_descriptor.
 * Caller frees the array (but not the const strings).
 *
 * Should be used from a qemu_plugin_register_vcpu_init_cb() callback
 * after the vCPU is initialised, i.e. in the vCPU context.
 */
QEMU_PLUGIN_API
GArray *qemu_plugin_get_registers(void);

/**
 * qemu_plugin_read_memory_vaddr() - read from memory using a virtual address
 *
 * @addr: A virtual address to read from
 * @data: A byte array to store data into
 * @len: The number of bytes to read, starting from @addr
 *
 * @len bytes of data is read starting at @addr and stored into @data. If @data
 * is not large enough to hold @len bytes, it will be expanded to the necessary
 * size, reallocating if necessary. @len must be greater than 0.
 *
 * This function does not ensure writes are flushed prior to reading, so
 * callers should take care when calling this function in plugin callbacks to
 * avoid attempting to read data which may not yet be written and should use
 * the memory callback API instead.
 *
 * Returns true on success and false on failure.
 */
QEMU_PLUGIN_API
bool qemu_plugin_read_memory_vaddr(uint64_t addr,
                                   GByteArray *data, size_t len);

/**
 * qemu_plugin_read_register() - read register for current vCPU
 *
 * @handle: a @qemu_plugin_reg_handle handle
 * @buf: A GByteArray for the data owned by the plugin
 *
 * This function is only available in a context that register read access is
 * explicitly requested via the QEMU_PLUGIN_CB_R_REGS flag.
 *
 * Returns the size of the read register. The content of @buf is in target byte
 * order. On failure returns -1.
 */
QEMU_PLUGIN_API
int qemu_plugin_read_register(struct qemu_plugin_register *handle,
                              GByteArray *buf);

/**
 * qemu_plugin_scoreboard_new() - alloc a new scoreboard
 *
 * @element_size: size (in bytes) for one entry
 *
 * Returns a pointer to a new scoreboard. It must be freed using
 * qemu_plugin_scoreboard_free.
 */
QEMU_PLUGIN_API
struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size);

/**
 * qemu_plugin_scoreboard_free() - free a scoreboard
 * @score: scoreboard to free
 */
QEMU_PLUGIN_API
void qemu_plugin_scoreboard_free(struct qemu_plugin_scoreboard *score);

/**
 * qemu_plugin_scoreboard_find() - get pointer to an entry of a scoreboard
 * @score: scoreboard to query
 * @vcpu_index: entry index
 *
 * Returns address of entry of a scoreboard matching a given vcpu_index. This
 * address can be modified later if scoreboard is resized.
 */
QEMU_PLUGIN_API
void *qemu_plugin_scoreboard_find(struct qemu_plugin_scoreboard *score,
                                  unsigned int vcpu_index);

/* Macros to define a qemu_plugin_u64 */
#define qemu_plugin_scoreboard_u64(score) \
    (qemu_plugin_u64) {score, 0}
#define qemu_plugin_scoreboard_u64_in_struct(score, type, member) \
    (qemu_plugin_u64) {score, offsetof(type, member)}

/**
 * qemu_plugin_u64_add() - add a value to a qemu_plugin_u64 for a given vcpu
 * @entry: entry to query
 * @vcpu_index: entry index
 * @added: value to add
 */
QEMU_PLUGIN_API
void qemu_plugin_u64_add(qemu_plugin_u64 entry, unsigned int vcpu_index,
                         uint64_t added);

/**
 * qemu_plugin_u64_get() - get value of a qemu_plugin_u64 for a given vcpu
 * @entry: entry to query
 * @vcpu_index: entry index
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_u64_get(qemu_plugin_u64 entry, unsigned int vcpu_index);

/**
 * qemu_plugin_u64_set() - set value of a qemu_plugin_u64 for a given vcpu
 * @entry: entry to query
 * @vcpu_index: entry index
 * @val: new value
 */
QEMU_PLUGIN_API
void qemu_plugin_u64_set(qemu_plugin_u64 entry, unsigned int vcpu_index,
                         uint64_t val);

/**
 * qemu_plugin_u64_sum() - return sum of all vcpu entries in a scoreboard
 * @entry: entry to sum
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_u64_sum(qemu_plugin_u64 entry);

/* ================ CPU State Snapshot/Rollback API ================ */

/*
 * struct qemu_plugin_cpu_state - Opaque handle to a saved CPU state
 *
 * Holds a raw memcpy snapshot of the target's CPUArchState execution
 * fields (plus the handful of CPUState fields a speculative walk can
 * dirty), not a per-register walk through the GDB register interface —
 * this also captures internal state (lazy flags, FPU, etc.) that GDB
 * register access would miss. Architecture-agnostic: works with any
 * target (x86, ARM, RISC-V, etc.).
 */
struct qemu_plugin_cpu_state;

/**
 * qemu_plugin_write_register() - write register for current vCPU
 *
 * @handle: a @qemu_plugin_reg_handle handle from qemu_plugin_get_registers()
 * @buf: A GByteArray containing the data to write, in target byte order
 *
 * This function is only available in a context that register write access is
 * explicitly requested via the QEMU_PLUGIN_CB_RW_REGS flag.
 *
 * Returns the number of bytes written. On failure returns -1.
 */
QEMU_PLUGIN_API
int qemu_plugin_write_register(struct qemu_plugin_register *handle,
                               GByteArray *buf);

/**
 * qemu_plugin_cpu_state_save() - snapshot all CPU registers
 *
 * Captures the complete execution state of the current vCPU via a raw
 * memcpy of its CPUArchState (architecture-agnostic: works with any
 * target). The returned handle must be freed with
 * qemu_plugin_cpu_state_free().
 *
 * This function is only available in a context that register read access is
 * explicitly requested via QEMU_PLUGIN_CB_R_REGS or QEMU_PLUGIN_CB_RW_REGS.
 *
 * Returns an opaque handle to the saved state, or NULL on failure.
 */
QEMU_PLUGIN_API
struct qemu_plugin_cpu_state *qemu_plugin_cpu_state_save(void);

/**
 * qemu_plugin_cpu_state_restore() - restore previously saved CPU registers
 *
 * @state: handle returned by qemu_plugin_cpu_state_save()
 *
 * Restores the complete register state of the current vCPU from a
 * previously saved snapshot.
 *
 * This function is only available in a context that register write access is
 * explicitly requested via QEMU_PLUGIN_CB_RW_REGS.
 *
 * Returns true on success, false on failure.
 */
QEMU_PLUGIN_API
bool qemu_plugin_cpu_state_restore(struct qemu_plugin_cpu_state *state);

/**
 * qemu_plugin_cpu_state_free() - free a CPU state snapshot
 *
 * @state: handle returned by qemu_plugin_cpu_state_save()
 *
 * Releases all memory associated with the state snapshot.
 */
QEMU_PLUGIN_API
void qemu_plugin_cpu_state_free(struct qemu_plugin_cpu_state *state);

/**
 * qemu_plugin_set_pc() - set the program counter of the current vCPU
 *
 * @pc: the new program counter value
 *
 * Sets the PC to the given address. Must be used together with
 * state save/restore for wrong-path execution scenarios.
 *
 * This function is only available in a context that register write access is
 * explicitly requested via QEMU_PLUGIN_CB_RW_REGS.
 */
QEMU_PLUGIN_API
void qemu_plugin_set_pc(uint64_t pc);

/**
 * qemu_plugin_get_pc() - get the current program counter
 *
 * Returns the current program counter of the current vCPU.
 * Useful for tracking PC changes during wrong-path execution.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_get_pc(void);

/**
 * qemu_plugin_exec_inline_insn() - execute one instruction at current PC
 *
 * Translates and executes exactly one instruction at the current program
 * counter. Plugin instrumentation callbacks are suppressed during this
 * execution to avoid recursive callbacks.
 *
 * This is designed for wrong-path simulation: save state, set PC to wrong
 * target, execute instructions one at a time collecting memory accesses,
 * then restore state.
 *
 * Returns true on success, false on failure (e.g. unmapped address).
 */
QEMU_PLUGIN_API
bool qemu_plugin_exec_inline_insn(void);

/**
 * qemu_plugin_exec_tb() - execute one full translation block at current PC
 *
 * Translates and executes a complete basic block at the current program
 * counter.  All plugin callbacks fire (tb_exec, insn_exec, inline ops,
 * mem, translation), so the plugin sees the speculative TB the same
 * shape it sees a normal CP TB.  The plugin is responsible for keeping
 * its own state separated when fired from inside a spec-mode block —
 * for example by short-circuiting CP-only state mutations and by
 * saving/restoring any scoreboard slots clobbered by inline stores
 * around qemu_plugin_spec_mode_begin/_end.
 *
 * After return, qemu_plugin_get_pc() reflects where the branch at the
 * end of the block went.
 *
 * Returns true on success, false on failure (e.g. unmapped address,
 * exception during execution).
 */
QEMU_PLUGIN_API
bool qemu_plugin_exec_tb(void);

/* ================ Speculative Store Buffer API ================ */

/**
 * qemu_plugin_spec_mode_begin() - enter speculative execution mode
 *
 * Initializes the per-CPU speculative store buffer. While active,
 * all guest memory writes from instruction execution are redirected
 * to a local cache instead of modifying real guest memory. Guest
 * memory reads check the buffer first for store-to-load forwarding.
 *
 * This is designed for wrong-path execution: enter speculative mode
 * before executing wrong-path instructions, then call
 * qemu_plugin_spec_mode_end() to discard all speculative writes.
 *
 * @saved_state: optional CPU state snapshot taken before wrong-path
 *               execution.  If non-NULL and an exception longjmps
 *               out of wrong-path execution, the cleanup handler
 *               restores this snapshot before resuming normal
 *               execution.  Ownership remains with the caller on
 *               the normal (non-exception) path.
 *
 * Must be paired with qemu_plugin_spec_mode_end().
 */
QEMU_PLUGIN_API
void qemu_plugin_spec_mode_begin(struct qemu_plugin_cpu_state *saved_state);

/**
 * qemu_plugin_spec_mode_end() - exit speculative execution mode
 *
 * Discards all speculative writes accumulated since
 * qemu_plugin_spec_mode_begin() and returns to normal execution.
 * Real guest memory is unmodified.
 */
QEMU_PLUGIN_API
void qemu_plugin_spec_mode_end(void);

/**
 * qemu_plugin_spec_vtime_pause() - freeze the guest virtual clock
 *
 * Pause the guest's virtual clock (QEMU_CLOCK_VIRTUAL) for the duration of a
 * wrong-path excursion so the speculative run's host wall-clock time does not
 * advance the guest's architected timer counters (e.g. aarch64 CNTVCT, x86
 * TSC, riscv ``time``, mips Count).  Call once at the OUTER excursion boundary,
 * before qemu_plugin_spec_mode_begin(); pair with qemu_plugin_spec_vtime_resume().
 * Idempotent and a no-op in user-mode emulation.
 */
QEMU_PLUGIN_API
void qemu_plugin_spec_vtime_pause(void);

/**
 * qemu_plugin_spec_vtime_resume() - resume the guest virtual clock
 *
 * Undo qemu_plugin_spec_vtime_pause(), discarding the wall-clock interval the
 * excursion consumed so the guest's architected counters read the same value
 * after the excursion as before it.  Call once at the OUTER excursion boundary,
 * after qemu_plugin_spec_mode_end().
 */
QEMU_PLUGIN_API
void qemu_plugin_spec_vtime_resume(void);

/**
 * qemu_plugin_vclock_pause() - freeze the guest clock for instrumentation work
 *
 * Nestable.  Wrap plugin work that runs on the vCPU thread but is not guest
 * execution (translation-time decoding, per-TB trace emission) so its host
 * wall-clock cost is not charged to guest time.  Without it, instrumented
 * guest interrupt handlers can cost more guest time than one timer period and
 * the guest collapses into a tick storm.  Pair with
 * qemu_plugin_vclock_resume(); no-op in user-mode emulation.
 */
QEMU_PLUGIN_API
void qemu_plugin_vclock_pause(void);

/**
 * qemu_plugin_vclock_resume() - undo one qemu_plugin_vclock_pause()
 */
QEMU_PLUGIN_API
void qemu_plugin_vclock_resume(void);

/**
 * qemu_plugin_in_async_int() - is the vCPU inside an async-interrupt handler?
 *
 * Returns true while the executing vCPU is handling an asynchronous interrupt
 * (timer/device IRQ/FIQ/SError) — from the interrupt's exception entry until
 * the exception return that lands back at the interrupted PC, spanning any
 * scheduler context-switch or nested sync/async exception in between.  False
 * for synchronous entries alone (syscall/SVC, faults).  A system-mode tracer
 * reads this to drop the async handler from the trace (non-representative OS
 * noise) while keeping synchronous syscalls/faults.  Always false in user-mode
 * emulation and on targets whose exception path is not yet instrumented.
 */
QEMU_PLUGIN_API
bool qemu_plugin_in_async_int(void);

/**
 * qemu_plugin_in_spec_mode() - is the vCPU executing speculatively?
 *
 * Returns true while the executing vCPU is inside a plugin-driven
 * speculative (wrong-path) session — between qemu_plugin_spec_mode_begin()
 * and qemu_plugin_spec_mode_end().  This is the QEMU-side ground truth for
 * the mode, read from the vCPU itself: a callback fired by a speculative
 * execution observes true here even if the plugin's own thread-local
 * session state is not visible to the invoking context.  False when no
 * vCPU is current.
 */
QEMU_PLUGIN_API
bool qemu_plugin_in_spec_mode(void);

/*
 * Ordered per-vCPU path events — the event-stream alternative to
 * edge-detecting the accumulated fault/async state above.  Each fault
 * entry/return and async-window edge is appended at its QEMU chokepoint,
 * in order, with the address-space id and privilege level stamped at the
 * event instant.  Only populated after a plugin opts in per vCPU via
 * qemu_plugin_cpu_events_set(); the producing and consuming thread are
 * both the owning vCPU thread.
 */
enum qemu_plugin_cpu_event_kind {
    QEMU_PLUGIN_CPU_EV_FAULT_ENTER  = 0,
    QEMU_PLUGIN_CPU_EV_FAULT_RETURN = 1,
    QEMU_PLUGIN_CPU_EV_ASYNC_ENTER  = 2,
    QEMU_PLUGIN_CPU_EV_ASYNC_RETURN = 3,
    /*
     * A committed architectural write that changed the address-space
     * register qemu_plugin_get_addr_space_id() reports (MIPS
     * EntryHi.ASID, Arm TTBR0_EL1, RISC-V SATP, x86 CR3).  Field
     * semantics FOR THIS KIND differ from the fault/async kinds:
     * @asid is the NEW value just committed, @pc carries the OLD value
     * it replaced (not a PC), @priv is the privilege the write executed
     * at and @depth_after the live fault-stack depth.  Emitted only in
     * system mode, only when the reported value actually changes, and
     * never on the wrong path.  Every OS must execute this privileged,
     * expensive operation to switch address spaces, so the event stream
     * makes address-space swap mechanics (PTI-style kernel entry
     * switches, TLB-maintenance save/probe writes, committed context
     * switches) observable without any OS-specific assumption.
     */
    QEMU_PLUGIN_CPU_EV_ASID_WRITE   = 4,
};

struct qemu_plugin_cpu_event {
    uint8_t  kind;          /* enum qemu_plugin_cpu_event_kind */
    uint8_t  priv;          /* privilege level at the event instant */
    /*
     * Whether @tp below named the executing software thread at the event
     * instant: set when the event fired at user privilege (every target's
     * thread pointer names the thread there) or where the target reports
     * qemu_plugin_thread_ptr_tracks_current() in the event's context.
     * When clear, @tp is whatever the register held and identifies no
     * guest thread (e.g. an interrupt delivered into M-mode firmware).
     */
    uint8_t  tp_ok;
    uint32_t depth_after;   /* fault-stack depth after this event */
    uint64_t pc;            /* resume PC (fault) / departure PC (async) */
    uint64_t asid;          /* address-space id at the event instant */
    /*
     * qemu_plugin_get_thread_ptr() sampled at the event instant — for an
     * ASYNC_ENTER, the thread the interrupt was DELIVERED in, read before
     * any handler instruction runs.  The delivery context is otherwise
     * unrecoverable by the consumer: the event is drained at the next
     * executed TB, by which point the vCPU is already inside the handler
     * (or further), and on an SMP guest the delivering context may be one
     * the plugin never gets another look at.
     */
    uint64_t tp;
};

/**
 * qemu_plugin_cpu_events_set() - enable/disable the vCPU path-event queue
 * @vcpu_index: which vCPU
 * @enabled: true to start collecting events (clears any prior backlog)
 *
 * Must be called from the vCPU's own thread (e.g. a tb_exec callback) or
 * before the vCPU runs.
 */
QEMU_PLUGIN_API
void qemu_plugin_cpu_events_set(unsigned int vcpu_index, bool enabled);

/**
 * qemu_plugin_drain_cpu_events() - consume the vCPU's pending path events
 * @vcpu_index: which vCPU
 * @evs: out — pointer to the drained events (valid until the next drain
 *       or events_set call on this vCPU)
 *
 * Returns the number of drained events and resets the queue.  Call from
 * the owning vCPU thread only.
 */
QEMU_PLUGIN_API
size_t qemu_plugin_drain_cpu_events(unsigned int vcpu_index,
                                    const struct qemu_plugin_cpu_event **evs);

/**
 * qemu_plugin_async_int_reset() - force-clear the async-interrupt flag
 *
 * Clears qemu_plugin_in_async_int() for the executing vCPU.  A tracer calls
 * this at a known-clean point (e.g. opening a trace segment with the traced
 * process at user level) to discard any stale state left by a pre-segment
 * interrupt whose exception return never matched its departure PC.
 */
QEMU_PLUGIN_API
void qemu_plugin_async_int_reset(void);

/**
 * qemu_plugin_fault_depth() - current synchronous-fault nesting depth
 *
 * Returns the executing vCPU's live fault-stack depth: the number of
 * synchronous fault deliveries (whose handlers re-execute the faulting
 * instruction on exception return) not yet matched by their exception
 * return.  Unlike async interrupts (dropped via qemu_plugin_in_async_int()),
 * synchronous faults are KEPT — the handler is real workload-induced code —
 * so a tracer reads this depth to tag handler code with its nesting level.
 * QEMU owns the underlying resume-PC stack and maintains it synchronously at
 * each delivery/return chokepoint, so the value is exact even under dense
 * nested faults.  The ordered per-vCPU event queue above carries the same
 * transitions as FAULT_ENTER/FAULT_RETURN events with per-event depth_after
 * stamps; this accessor reads the live depth at a point in time (e.g. to
 * baseline a trace window) without consuming events.  Reads zero in
 * ``*-linux-user`` and on uninstrumented targets.  Must be called from a vCPU
 * context (e.g. an exec callback).
 */
QEMU_PLUGIN_API
uint32_t qemu_plugin_fault_depth(void);

/**
 * qemu_plugin_rep_iterations() - architectural iteration count of the
 * self-loop instruction the executing vCPU just ran
 *
 * Returns how many iterations the most recently executed fan-out
 * instruction — today an x86 REP-prefixed string operation — actually
 * retired during that one execution.  The value is produced by the target
 * translation from the loop counter's own decrement (CX/ECX/RCX selected by
 * the address size), so it is architectural truth and not a count of
 * delivered instrumentation callbacks.
 *
 * This distinction is load-bearing because a REP is not always translated as
 * a loop: exactly one iteration is generated whenever CF_USE_ICOUNT or
 * CF_SINGLE_STEP is in the TB's cflags, or EFLAGS.TF or the interrupt shadow
 * is set, and an exception or interrupt taken between iterations splits an
 * already-looping REP the same way.  A tracer that inferred the iteration
 * count from how many memory-op callbacks arrived in one execution would
 * therefore report a different count — and a different trace shape — for
 * identical guest execution.  Reading it here does not.
 *
 * Zero has two meanings, separated by qemu_plugin_rep_complete(): a REP
 * entered with a zero counter (complete, and a real retired instruction),
 * or the trailing pass QEMU makes over an instruction it has already
 * finished when it translated only a single iteration (also complete, but
 * not a new instruction — the caller should recognise it as a continuation
 * of the instruction whose iterations it has already seen).
 *
 * Valid for the instruction most recently executed on this vCPU, so read it
 * before running any further guest code (a wrong-path excursion included).
 * Reads zero on targets with no fan-out instruction.  Must be called from a
 * vCPU context (e.g. an exec callback).
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_rep_iterations(void);

/**
 * qemu_plugin_rep_complete() - did the self-loop instruction retire?
 *
 * True when the fan-out instruction reported by
 * qemu_plugin_rep_iterations() finished during that execution: its loop
 * counter reached zero, or a REPZ/REPNZ flag condition broke the
 * repetition.  False means QEMU will re-enter the same instruction to
 * continue it — because it translated a single iteration, because it hit an
 * internal chunk bound, or because an exception intervened — so more
 * iterations of the same instruction are still to come.
 *
 * A tracer that models each iteration as its own control-flow event uses
 * this to decide the last iteration's successor: an execution that did not
 * retire loops back to the instruction, one that did falls through past it.
 * That makes the emitted shape independent of how many iterations QEMU
 * happened to pack into one execution.
 *
 * Must be called from a vCPU context, before any further guest code runs.
 */
QEMU_PLUGIN_API
bool qemu_plugin_rep_complete(void);

/**
 * qemu_plugin_rep_pc() - which instruction the self-loop accounting describes
 *
 * Returns the virtual address of the fan-out instruction whose counts
 * qemu_plugin_rep_iterations() and qemu_plugin_rep_complete() report — the
 * same address qemu_plugin_insn_vaddr() gives for that instruction.  A
 * consumer that reads the accounting later than the execution it belongs to,
 * or on a target with no fan-out instruction at all (where the value stays
 * zero), compares this against the instruction it is attributing and falls
 * back instead of crediting another instruction's count.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_rep_pc(void);

/**
 * qemu_plugin_rep_reenter() - will QEMU re-enter the self-loop instruction?
 *
 * True when the execution reported by qemu_plugin_rep_iterations() left by
 * jumping back to the instruction's own address instead of past it, so the
 * same instruction is about to be executed again.  Unlike
 * qemu_plugin_rep_complete() this is an implementation fact rather than an
 * architectural one, and it exists to make one artefact identifiable: a REP
 * that QEMU translated as a single iteration re-enters itself even after the
 * iteration that exhausted the counter, and that final re-entry performs zero
 * iterations.  A consumer that models every iteration as an instruction uses
 * this to recognise that zero-iteration execution as the same instruction
 * finishing — not a new one — and so keep its instruction count independent
 * of how QEMU translated the REP.
 *
 * True is also reported at QEMU's internal repetition bound, where a long
 * REP is deliberately split into several executions to let the main loop run.
 */
QEMU_PLUGIN_API
bool qemu_plugin_rep_reenter(void);

/**
 * qemu_plugin_rep_bytes() - bulk bytes the reported execution moved
 *
 * The architectural byte progress of the execution described by
 * qemu_plugin_rep_pc(): for an AArch64 FEAT_MOPS SET/CPY execution this
 * is the amount the instruction's own size register was decremented by,
 * accumulated step by step so a fault mid-instruction leaves exactly the
 * bytes that were transferred.  A consumer whose fan-out unit is one
 * memory access (rather than an architectural iteration) uses this as
 * the register-derived truth to verify the delivered access stream
 * against: the sizes of the reported accesses must sum to it.  Targets
 * that publish an iteration count instead (x86 REP) leave it 0.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_rep_bytes(void);

/**
 * qemu_plugin_rep_chunk_boundary() - did the re-enter sit on a canonical
 * chunk boundary?
 *
 * Qualifies qemu_plugin_rep_reenter(): true when the execution left the
 * instruction at the point where QEMU's canonical loop translation itself
 * re-enters — its internal repetition bound, reached when the written-back
 * counter is one above a non-zero multiple of the bound (65536), under the
 * instruction's address-size mask.  A looping translation only ever
 * re-enters there, so its re-entries always report true; a single-iteration
 * translation (-icount, single-step, TF, the interrupt shadow) re-enters
 * after every iteration and reports true only at those same counter values.
 *
 * This is what lets a consumer reproduce, from any translation, the
 * per-TB-execution instruction count the canonical translation produces —
 * the count a per-TB inline counter (the bbv plugin feeding SimPoint
 * clustering, or this plugin's own scoreboard) observes when no
 * single-iteration lever is engaged: count executions, keep re-entries
 * that report true, discard re-entries that report false.  Meaningless
 * unless qemu_plugin_rep_reenter() is true.
 */
QEMU_PLUGIN_API
bool qemu_plugin_rep_chunk_boundary(void);

/**
 * qemu_plugin_spec_store_overflowed() - did the current wrong-path excursion's
 * speculative-store footprint cross the soft budget?
 *
 * True when a single wrong-path instruction wrote a garbage-size region into
 * the speculative store sandbox without faulting (it is buffered, not real),
 * crossing PLUGIN_SPEC_STORE_SOFT_BUDGET lines.  A normal wpdepth-bounded
 * excursion never trips this; the wrong-path loop should poll it and terminate
 * the excursion so the sandbox is not filled to its hard cap (which would
 * silently drop later speculative stores).  Always false in user mode / outside
 * spec mode.
 */
QEMU_PLUGIN_API
bool qemu_plugin_spec_store_overflowed(void);

/**
 * qemu_plugin_spec_mem_faulted_take() - did the just-executed wrong-path memory
 * access read a synthetic placeholder?
 *
 * Returns true (and clears the sentinel) when the memory access the current
 * vCPU just performed on the wrong (speculative) path landed on an
 * absent/unreadable page and was served a deterministic placeholder value
 * instead of real memory — the excursion continues, but the value is
 * synthetic.  A tracer calls this from its memory callback (which fires
 * immediately after the access) to tag that memop as a synthetic-data fault.
 * Reads false (and is a no-op) outside wrong-path execution and in user mode
 * for accesses that hit real memory.  Consumes the flag, so a second call for
 * the same access returns false.  Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
bool qemu_plugin_spec_mem_faulted_take(void);

/**
 * qemu_plugin_spec_syscall_blocked_count() - wrong-path syscalls refused
 *
 * Returns how many times a syscall was refused because the vCPU issuing it was
 * on a plugin wrong path.  A speculative walk fetches and executes whatever
 * the guest has ahead of a mispredicted branch, including syscall
 * instructions; the walk continues past them at their architectural
 * fall-through, but the call itself must never be performed, because in
 * ``*-linux-user`` it is served by the HOST and would produce real side effects on
 * a path the guest never takes.  That suppression is structural — a syscall
 * instruction executed under qemu_plugin_spec_mode_begin() unwinds into
 * qemu_plugin_exec_tb()'s landing pad, never into the syscall dispatcher — so
 * this counter is a standing self-check rather than a policy knob and reads 0
 * on a healthy run; a non-zero value means the suppression developed a hole
 * and the trace ran with real side effects on it.  Always 0 in system
 * emulation, where a syscall is guest kernel entry and has no host effect.
 * Process-wide (all vCPUs); safe to call from plugin_exit().
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_spec_syscall_blocked_count(void);

/**
 * qemu_plugin_spec_clear_exception() - drop a pending speculative exception
 *
 * Clears the guest exception a wrong-path EXECUTION-TIME fault latched when it
 * longjmped out of a speculative qemu_plugin_exec_tb() (x86 #DE/#UD/#GP/#AC,
 * INTO/BOUND; MIPS arithmetic overflow, teq-family trap).  The raise path
 * (raise_exception_ra / cpu_loop_exit_restore) already unwound the guest PC
 * back to the faulting instruction and left cpu->exception_index set; a
 * wrong-path walker that skips the faulting insn and re-dispatches must call
 * this first so the next speculative exec_tb starts with no exception pending.
 * Sets exception_index to EXCP_NONE (-1 in common code, as cpu_loop_exit_noexc
 * does).  Any arch-specific latch (x86 error_code, etc.) is register state
 * covered by the CPUArchState snapshot restored wholesale at excursion end and
 * is inert unless an exception is actually delivered, which the walker never
 * does.  Only meaningful between qemu_plugin_spec_mode_begin() and _end().
 * Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
void qemu_plugin_spec_clear_exception(void);

/**
 * qemu_plugin_get_priv_level() - current privilege level of the executing vCPU
 *
 * Returns a normalized privilege ordinal: 0 = user / least privileged,
 * larger = more privileged (kernel/supervisor/hypervisor).  In ``*-linux-user``
 * this is always 0.  Lets a plugin tell user-space execution from kernel /
 * system execution (e.g. to count only the target program's user-space
 * instructions, or stamp a kernel-vs-user bit).  Must be called from a vCPU
 * context (e.g. an exec callback).
 */
QEMU_PLUGIN_API
int qemu_plugin_get_priv_level(void);

/**
 * qemu_plugin_get_addr_space_id() - current address-space id of the vCPU
 *
 * Returns the architectural identifier of the current address space — the
 * page-table base / ASID register (x86 CR3, RISC-V SATP, Arm TTBR, MIPS
 * ASID).  Unique per process address space, so a plugin can pin tracing to a
 * single target process.  Returns 0 in ``*-linux-user`` (one address space).
 * Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_get_addr_space_id(void);

/**
 * qemu_plugin_paging_enabled() - whether the guest MMU / paging is enabled
 *
 * Returns true when the executing vCPU's MMU / paging translation is active
 * (x86 CR0.PG, Arm SCTLR.M, RISC-V SATP!=Bare; MIPS always has a TLB so
 * reports true), false otherwise.  Always true in ``*-linux-user``.  A plugin
 * that speculatively executes wrong-path code relies on the MMU to fault on
 * fetches into non-code; with paging disabled there is no such bound, so the
 * plugin should refrain from speculating.  Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
bool qemu_plugin_paging_enabled(void);

/**
 * qemu_plugin_vaddr_to_paddr() - translate a guest-virtual address
 * @vaddr: guest-virtual address in the vCPU's CURRENT address space
 * @paddr: filled with the guest-physical translation on success
 *
 * Debug-walks the current address space's translation (page tables, or
 * the live software TLB on TLB-refill architectures such as MIPS)
 * without perturbing it.  Returns false when no translation exists
 * right now — on a TLB-refill architecture that includes mappings the
 * guest TLB has evicted, so a false is "unknown", not "unmapped".
 *
 * Physical addresses are the one architectural identity virtual
 * aliases cannot forge: two processes mapping the same virtual page to
 * different content necessarily map different physical pages, while a
 * narrow, recycled ASID (MIPS EntryHi.ASID) can silently alias them.
 * A plugin pinned to one process can therefore verify address-space
 * identity by physical page when the ASID value alone is ambiguous.
 * In ``*-linux-user`` (one address space, no guest MMU) the identity map
 * is returned.  Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
bool qemu_plugin_vaddr_to_paddr(uint64_t vaddr, uint64_t *paddr);

/**
 * qemu_plugin_vaddr_is_kernel() - classify a code VA's privilege domain
 * @vaddr: a guest-virtual code (instruction-fetch) address
 *
 * Returns true when @vaddr lies in the guest's KERNEL (privileged) code
 * region and false when it lies in the USER region, as decided by the
 * target's own MMU / segment logic: the canonical upper half (x86_64), the
 * TTBR1 region select (AArch64), the sign-extended kernel half for the
 * active paging mode (RISC-V Sv39/48/57), or the fixed segment map (MIPS
 * kuseg vs kseg).  Kernel and user virtual-address ranges are architecturally
 * disjoint, so this is a pure range/bit test that never walks page tables and
 * never faults — safe to call on a speculatively-fetched wrong-path address,
 * and independent of the current privilege level (which speculative execution
 * can mis-observe).
 *
 * Returns false unconditionally in ``*-linux-user`` (no kernel address space) and
 * on any target that does not implement the classification.  Must be called
 * from a vCPU context.
 */
QEMU_PLUGIN_API
bool qemu_plugin_vaddr_is_kernel(uint64_t vaddr);

/**
 * qemu_plugin_get_thread_ptr() - the guest's per-thread pointer register
 *
 * Returns the per-software-thread pointer state the guest kernel
 * maintains: x86_64 FS.base (GS.base for a 32-bit compat task), AArch64
 * TPIDR_EL0, MIPS CP0 UserLocal — the TLS base, context-switched per
 * thread — and on RISC-V the kernel's current-task pointer (sscratch
 * while in user, tp while in kernel: the S-mode trap entry swaps the
 * two, so that pair is the one value space that names the task at every
 * privilege; a guest that never arms sscratch degrades to the raw tp).
 * In every case the value is a stable per-guest-thread identity that
 * survives vCPU migration — unlike the vCPU index, which names a
 * scheduling slot, not a thread.
 *
 * A sample taken above user privilege is meaningful only where
 * qemu_plugin_thread_ptr_tracks_current() reports true in that context.
 * Returns 0 when the target provides no hook or the state was never
 * written (e.g. a CPU model without the feature, or a guest that sets
 * no TLS); threads without a thread pointer are architecturally
 * indistinguishable.  Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
uint64_t qemu_plugin_get_thread_ptr(void);

/**
 * qemu_plugin_thread_ptr_tracks_current() - is the thread pointer valid
 *                                           above user privilege?
 *
 * Reports whether the register qemu_plugin_get_thread_ptr() reads keeps
 * naming the software thread the vCPU is executing when sampled inside
 * the kernel — i.e. whether the guest kernel reloads it from the incoming
 * task at every context switch and otherwise leaves it alone.  Where this
 * is true a plugin can follow a guest task switch that happens entirely
 * in kernel code (a freshly cloned child taking over before it has ever
 * run a user instruction, a kernel thread scheduled in, a handler running
 * after the scheduler moved on) instead of attributing that work to
 * whichever thread last entered the kernel on that vCPU.
 *
 * The answer is a property of the SAMPLING CONTEXT, not a flat target
 * property: re-ask it at each privileged sample rather than latching one
 * answer per run.  True for MIPS (CP0 UserLocal), AArch64 (TPIDR_EL0)
 * and x86-64 (FS.base) at every privilege.  True for RISC-V at U/S
 * privilege — the reported value there is the kernel's current-task
 * pointer (see qemu_plugin_get_thread_ptr()) — but false in M-mode
 * firmware (which runs on its own tp with the S-mode sscratch parked)
 * and under H-extension virtualization.  False on any target without
 * the thread-pointer hook.  Must be called from a vCPU context.
 */
QEMU_PLUGIN_API
bool qemu_plugin_thread_ptr_tracks_current(void);

/**
 * qemu_plugin_icount_enabled() - whether QEMU is running with -icount
 *
 * Returns true when instruction-count timing is active.  Under icount the
 * guest virtual clock is driven by the instruction count rather than host
 * wall-clock, so the wrong-path virtual-clock freeze (cpu_disable_ticks) does
 * NOT stop guest time from advancing during a speculative excursion.  A plugin
 * that speculatively executes wrong-path code should refrain from speculating
 * under icount (the excursion's instructions would leak into guest time).
 * Always false in ``*-linux-user``.
 */
QEMU_PLUGIN_API
bool qemu_plugin_icount_enabled(void);

#endif /* QEMU_QEMU_PLUGIN_H */
