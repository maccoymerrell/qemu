/*
 * Plugin Shared Internal Functions
 *
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include <gmodule.h>
#include "qemu/queue.h"
#include "qemu/qht.h"

#define QEMU_PLUGIN_MIN_VERSION 2

/* global state */
struct qemu_plugin_state {
    QTAILQ_HEAD(, qemu_plugin_ctx) ctxs;
    QLIST_HEAD(, qemu_plugin_cb) cb_lists[QEMU_PLUGIN_EV_MAX];
    /*
     * Use the HT as a hash map by inserting k == v, which saves memory as
     * documented by GLib. The parent struct is obtained with container_of().
     */
    GHashTable *id_ht;
    /*
     * Use the HT as a hash map. Note that we could use a list here,
     * but with the HT we avoid adding a field to CPUState.
     */
    GHashTable *cpu_ht;
    QLIST_HEAD(, qemu_plugin_scoreboard) scoreboards;
    size_t scoreboard_alloc_size;
    DECLARE_BITMAP(mask, QEMU_PLUGIN_EV_MAX);
    /*
     * @lock protects the struct as well as ctx->uninstalling.
     * The lock must be acquired by all API ops.
     * The lock is recursive, which greatly simplifies things, e.g.
     * callback registration from qemu_plugin_vcpu_for_each().
     */
    QemuRecMutex lock;
    /*
     * HT of callbacks invoked from helpers. All entries are freed when
     * the code cache is flushed.
     */
    struct qht dyn_cb_arr_ht;
    /* How many vcpus were started */
    int num_vcpus;
};


struct qemu_plugin_ctx {
    GModule *handle;
    qemu_plugin_id_t id;
    struct qemu_plugin_cb *callbacks[QEMU_PLUGIN_EV_MAX];
    QTAILQ_ENTRY(qemu_plugin_ctx) entry;
    /*
     * keep a reference to @desc until uninstall, so that plugins do not have
     * to strdup plugin args.
     */
    struct qemu_plugin_desc *desc;
    /*
     * The API version the plugin exported through qemu_plugin_version, kept
     * past the load-time range check.  The loader admits every version in
     * [QEMU_PLUGIN_MIN_VERSION, QEMU_PLUGIN_VERSION], so this number is the
     * only thing that distinguishes two incompatible spellings of the same
     * entry point; discarding it is what makes an ABI change undetectable.
     */
    int version;
    bool installing;
    bool uninstalling;
    bool resetting;
};

struct qemu_plugin_ctx *plugin_id_to_ctx_locked(qemu_plugin_id_t id);

/*
 * The lowest API version any loaded plugin declared, for entry points that
 * carry no plugin id and so cannot ask about their own caller.
 */
void plugin_note_declared_version(int version);
int plugin_declared_version_floor(void);

void plugin_register_inline_op_on_entry(GArray **arr,
                                        enum qemu_plugin_mem_rw rw,
                                        enum qemu_plugin_op op,
                                        qemu_plugin_u64 entry,
                                        uint64_t imm);

void plugin_reset_uninstall(qemu_plugin_id_t id,
                            qemu_plugin_simple_cb_t cb,
                            bool reset);

void plugin_register_cb(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                        void *func);

void plugin_unregister_cb__locked(struct qemu_plugin_ctx *ctx,
                                  enum qemu_plugin_event ev);

void
plugin_register_cb_udata(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                         void *func, void *udata);

void
plugin_register_dyn_cb__udata(GArray **arr,
                              qemu_plugin_vcpu_udata_cb_t cb,
                              enum qemu_plugin_cb_flags flags, void *udata);

void
plugin_register_dyn_cond_cb__udata(GArray **arr,
                                   qemu_plugin_vcpu_udata_cb_t cb,
                                   enum qemu_plugin_cb_flags flags,
                                   enum qemu_plugin_cond cond,
                                   qemu_plugin_u64 entry,
                                   uint64_t imm,
                                   void *udata);

void plugin_register_vcpu_mem_cb(GArray **arr,
                                 void *cb,
                                 enum qemu_plugin_cb_flags flags,
                                 enum qemu_plugin_mem_rw rw,
                                 void *udata);

void exec_inline_op(enum plugin_dyn_cb_type type,
                    struct qemu_plugin_inline_cb *cb,
                    int cpu_index);

int plugin_num_vcpus(void);

struct qemu_plugin_scoreboard *plugin_scoreboard_new(size_t element_size);

void plugin_scoreboard_free(struct qemu_plugin_scoreboard *score);


/* Queue-non-empty scoreboard slot plumbing (see plugins/core.c). */
void plugin_set_evq_pending_slot(qemu_plugin_u64 slot, bool set);
bool plugin_evq_pending_slot_armed(void);
void plugin_evq_note_drained(CPUState *cpu);

/**
 * qemu_plugin_fillin_mode_info() - populate mode specific info
 * info: pointer to qemu_info_t structure
 */
void qemu_plugin_fillin_mode_info(qemu_info_t *info);

/**
 * qemu_plugin_vclock_agency_mode - track the PLUGIN-ACTIVE condition
 * @active: true when the first plugin installs, false when the last
 *          uninstalls
 *
 * The event-agency discipline (qemu/vclock-agency.h) is gated on the
 * runtime condition "a plugin is loaded/instrumenting", never on an
 * environment knob.  System-mode implementation arms the discipline
 * (plugins/system.c); user-mode is a no-op (plugins/user.c) -- there is
 * no iothread/VIRTUAL consumption split to move in user mode.
 */
void qemu_plugin_vclock_agency_mode(bool active);

#endif /* PLUGIN_H */
