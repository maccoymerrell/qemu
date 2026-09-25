/*
 * linux-user -pid: the deterministic guest process identity space.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <sys/syscall.h>
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qemu.h"
#include "user-internals.h"

/*
 * Deterministic guest process identity (-pid).
 *
 * A guest that asks for its own pid or tid is handed a number the host kernel
 * allocated, so two runs of the same binary read different numbers and
 * everything downstream of them differs with them: glibc's __tls_init_tp
 * stores the set_tid_address result into the TCB on every start-up, a lock
 * word derived from it differs, and an address computed from either differs.
 * -seed already pins the other host-derived input the guest reads at start-up
 * (AT_RANDOM); this pins the identity one.
 *
 * With -pid the thread group is renamed into a private space: the initial
 * thread is the given base and each further guest thread takes the next
 * number in the order the guest created it.  That order is deterministic
 * because clone() does not return to the guest until the new thread has
 * registered its own identity (clone_func signals the condvar do_fork waits
 * on).  Every syscall that hands the guest a pid maps host -> guest, and every
 * syscall that takes one maps guest -> host, so the guest can still signal,
 * schedule and wait on the threads it names.  A number the guest never learned
 * from us is not a name in this space and is refused with ESRCH rather than
 * passed to the host kernel, where it would name an unrelated process.
 *
 * The rename covers one thread group.  A guest that starts a new PROCESS has
 * an identity this scheme cannot name deterministically -- the child's
 * allocations interleave with the parent's under host scheduling -- so -pid
 * refuses the fork instead of handing back a run that is pinned in one process
 * and not in the other.
 */
pid_t qemu_vpid_base;
static QemuMutex vpid_mutex;
static GHashTable *vpid_h2g;   /* host tid -> guest tid */
static GHashTable *vpid_g2h;   /* guest tid -> host tid */
static int vpid_next_offset;

/* One locked lookup in either direction's table. */
static bool vpid_lookup(GHashTable *t, int key, int *out)
{
    gpointer v;
    bool found;

    qemu_mutex_lock(&vpid_mutex);
    found = g_hash_table_lookup_extended(t, GINT_TO_POINTER(key), NULL, &v);
    qemu_mutex_unlock(&vpid_mutex);
    if (found) {
        *out = GPOINTER_TO_INT(v);
    }
    return found;
}

/*
 * Enter the pinned space at @base.  -pid can arrive twice (QEMU_PID in the
 * environment and again on the command line, which is how every option is
 * allowed to be given); the tables are built once so the second one does
 * not orphan the first.
 */
void vpid_init(pid_t base)
{
    qemu_vpid_base = base;
    if (!vpid_h2g) {
        qemu_mutex_init(&vpid_mutex);
        vpid_h2g = g_hash_table_new(NULL, NULL);
        vpid_g2h = g_hash_table_new(NULL, NULL);
    }
}

/*
 * Give @host_tid the next name in the pinned identity space, once.  Called
 * from task_settid, which every guest thread runs before the clone that
 * created it returns to the guest, so the numbering follows the guest's own
 * clone order rather than the host's tid allocation.
 */
void vpid_register(pid_t host_tid)
{
    if (!qemu_vpid_base) {
        return;
    }
    qemu_mutex_lock(&vpid_mutex);
    if (!g_hash_table_contains(vpid_h2g, GINT_TO_POINTER(host_tid))) {
        pid_t guest_tid = qemu_vpid_base + vpid_next_offset++;
        g_hash_table_insert(vpid_h2g, GINT_TO_POINTER(host_tid),
                            GINT_TO_POINTER(guest_tid));
        g_hash_table_insert(vpid_g2h, GINT_TO_POINTER(guest_tid),
                            GINT_TO_POINTER(host_tid));
    }
    qemu_mutex_unlock(&vpid_mutex);
}

/* Name @host_tid carries in the pinned space, or 0 if it is not a guest
 * thread of this process. */
pid_t vpid_from_host(pid_t host_tid)
{
    int guest_tid;

    if (!qemu_vpid_base) {
        return host_tid;
    }
    return vpid_lookup(vpid_h2g, host_tid, &guest_tid) ? guest_tid : 0;
}

/*
 * Translate a pid/tid the guest passed us back into the host value, in place.
 * Returns false when the guest named a positive pid that is not in the pinned
 * space: it cannot have learned that number from us, and letting it through
 * would aim the syscall at an unrelated host process, so the caller answers
 * ESRCH.  Zero and negative arguments pass through untouched, as does every
 * argument when -pid is not in use; a negative that names a process group
 * (kill's -pgrp) is a group id, and its caller translates it with
 * vpid_pgrp_to_host() instead.
 */
bool vpid_to_host(abi_long *pid)
{
    int host_tid;

    if (!qemu_vpid_base || *pid <= 0) {
        return true;
    }
    if (!vpid_lookup(vpid_g2h, (int)*pid, &host_tid)) {
        return false;
    }
    *pid = host_tid;
    return true;
}

/*
 * The same, for a process-GROUP id.  The result side names this process's
 * group vpid_pgrp() -- it leads its own group in the pinned space -- so that
 * is a name in the space too, and on the host it is the group QEMU runs in.
 * It is the only group the guest can have learned from us; any other positive
 * id is refused like an unknown pid.  Zero and negative ids keep their kernel
 * meaning.
 */
bool vpid_pgrp_to_host(abi_long *pgrp)
{
    if (!qemu_vpid_base || (pid_t)*pgrp <= 0) {
        return true;
    }
    if ((pid_t)*pgrp != vpid_pgrp()) {
        return false;
    }
    *pgrp = getpgrp();
    return true;
}

pid_t vpid_self(void)
{
    pid_t host_tid = (pid_t)syscall(SYS_gettid);

    if (!qemu_vpid_base) {
        return host_tid;
    }
    /* Every guest thread registers in task_settid before its clone returns to
     * the guest, so the lookup below always hits; register defensively so a
     * future caller on an unregistered thread gets a name rather than a 0. */
    vpid_register(host_tid);
    return vpid_from_host(host_tid);
}

pid_t vpid_tgid(void)
{
    return qemu_vpid_base ? qemu_vpid_base : getpid();
}

/*
 * The guest's parent is whoever launched QEMU, which is outside the pinned
 * space and whose host pid differs between runs.  Linux already has a name
 * for that situation -- a process whose parent is not in its pid namespace
 * reads ppid 0 -- so use it rather than invent a number the guest could try
 * to signal.
 */
pid_t vpid_ppid(void)
{
    return qemu_vpid_base ? 0 : getppid();
}

/*
 * Process group and session.  In the pinned space the traced thread group is
 * alone, so it leads both; the host's real group and session ids are
 * inherited from the launching shell and differ between runs.
 */
pid_t vpid_pgrp(void)
{
    return qemu_vpid_base ? qemu_vpid_base : getpgrp();
}

pid_t vpid_sid(void)
{
    return qemu_vpid_base ? qemu_vpid_base : getsid(0);
}

/*
 * A guest that starts a new process leaves the space -pid can name.  Refuse
 * loudly: a run that silently continued would be pinned in the parent and
 * host-allocated in the child, which is exactly the irreproducibility the
 * option exists to remove, and it would be invisible in the result.
 */
void vpid_refuse_new_process(const char *what)
{
    error_report("-pid pins the guest's process identity for one thread "
                 "group, and this guest called %s to start another process. "
                 "Re-run without -pid (identity is then host-allocated and "
                 "the run is not reproducible), or use a guest that does not "
                 "start processes.", what);
    exit(EXIT_FAILURE);
}
