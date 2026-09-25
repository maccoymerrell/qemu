/*
 * vpid-pgrp: process-group ids under linux-user -pid (WP_TESTS.md net arm
 * F26, the quality audit's misc F26).
 *
 * With -pid the guest is told that its process group and session are its
 * pinned pid (getpgrp, getpgid, getsid).  A group id the guest learned that
 * way must name its own group when it hands the id back:
 *
 *   S1  kill(-getpgrp(), 0) succeeds: the caller is a member of that group
 *   S2  getpriority(PRIO_PGRP, getpgrp()) succeeds (the group exists)
 *   S3  getpgid(0) == getpgrp() (a control: a result, already translated)
 *
 * setpgid is not asserted: in the pinned space the guest also leads its
 * session (getsid() == getpid()), and Linux refuses setpgid to a session
 * leader, so there is no translated result to hold it to.
 *
 * Argument "bogus": S1 and S2 use a group id nobody holds (above pid_max),
 * so both must report FAIL -- the detector's own control.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int bogus = argc > 1 && strcmp(argv[1], "bogus") == 0;
    pid_t pid = getpid(), pgrp = getpgrp(), sid = getsid(0);
    pid_t g = bogus ? 0x3ffffff0 : pgrp;
    int fails = 0, r, e, p;

    printf("[vpid-pgrp] pid=%d pgrp=%d sid=%d%s\n", (int)pid, (int)pgrp,
           (int)sid, bogus ? " (bogus group id for S1/S2)" : "");

    errno = 0;
    r = kill(-g, 0);
    e = errno;
    printf("[vpid-pgrp] S1 kill(-%d, 0) = %d errno=%d (%s) -> %s\n", (int)g,
           r, e, e ? strerror(e) : "none", r == 0 ? "PASS" : "FAIL");
    fails += r != 0;

    errno = 0;
    p = getpriority(PRIO_PGRP, g);
    e = errno;
    printf("[vpid-pgrp] S2 getpriority(PRIO_PGRP, %d) = %d errno=%d (%s) -> "
           "%s\n", (int)g, p, e, e ? strerror(e) : "none",
           e == 0 ? "PASS" : "FAIL");
    fails += e != 0;

    r = getpgid(0);
    printf("[vpid-pgrp] S3 getpgid(0) = %d, getpgrp() = %d -> %s\n", r,
           (int)pgrp, r == pgrp ? "PASS" : "FAIL");
    fails += r != pgrp;

    printf("[vpid-pgrp] %d failures\n", fails);
    return fails ? 1 : 0;
}
