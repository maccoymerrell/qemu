/*
 * The same rule on the wrong path: a speculative excursion's fault is not
 * the guest's.
 *
 * The faulting cm.jalt here sits on the not-taken side of a taken branch,
 * so the correct path never executes it and a correct run must reach the
 * end untouched.  A plugin's wrong-path excursion does execute it, and
 * host_sigbus_handler() must leave that excursion rather than queue a
 * guest signal -- a queued signal outlives the excursion and is delivered
 * on the correct path, where nothing ever faulted.
 *
 * Run with the ChampSim Tracer, which is what drives QEMU's wrong-path
 * mode; see sigbus-code-fetch.h for how the fault itself is arranged.
 *
 * Copyright (c) 2026 Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sigbus-code-fetch.h"

static void handler(int sig)
{
    (void)sig;
    say("wrong-path fault leaked to the guest\n", 37);
    leave(3);
}

void _start(void)
{
    catch_sigbus(handler);
    set_jump_vector(unbacked_page());

    /*
     * t0 is 1, so the branch is not taken and the correct path runs
     * straight through.  The wrong path is the other direction.
     */
    __asm__ __volatile__(
        "li t0, 1\n"
        "beqz t0, 8f\n"
        "nop\n"
        "j 9f\n"
        "8:\n"
        CM_JALT_32 "\n"
        "nop\n"
        "nop\n"
        "9:\n"
        : : : "t0", "ra", "memory");

    say("correct path complete\n", 22);
    leave(0);
}
