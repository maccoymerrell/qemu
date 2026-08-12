/*
 * A host fault on a guest code read is a guest signal, not a QEMU bug.
 *
 * See sigbus-code-fetch.h for how the fault is arranged.  Only SIGBUS is
 * caught: a SIGSEGV, or no signal at all, must fail this test rather than
 * pass through a handler that cannot tell them apart.
 *
 * Copyright (c) 2026 Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sigbus-code-fetch.h"

static void handler(int sig)
{
    (void)sig;
    /*
     * The faulting cm.jalt is restarted on return from the handler and
     * would fault again, so leave from here.
     */
    say("SIGBUS delivered to the guest\n", 30);
    leave(0);
}

void _start(void)
{
    catch_sigbus(handler);
    set_jump_vector(unbacked_page());

    __asm__ __volatile__(CM_JALT_32 : : : "ra", "memory");

    die("no signal\n", 10);
}
