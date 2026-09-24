/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Imagination Technologies
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "hw/timer/mips_gictimer.h"

#define TIMER_PERIOD 10 /* 10 ns period for 100 Mhz frequency */

uint32_t mips_gictimer_get_freq(MIPSGICTimerState *gic)
{
    return NANOSECONDS_PER_SECOND / TIMER_PERIOD;
}

static void gic_vptimer_update(MIPSGICTimerState *gictimer,
                                   uint32_t vp_index, uint64_t now)
{
    uint64_t next;
    uint32_t wait;

    wait = gictimer->vptimers[vp_index].comparelo - gictimer->sh_counterlo -
           (uint32_t)(now / TIMER_PERIOD);
    /*
     * The programmed target is NOT IN THE FUTURE -- compare already equals
     * the count, or it is behind it -- so equality-match semantics put the
     * next match a full 2^32 ticks away, 42.95 s at this timer's 100 MHz.
     * Re-arm at 2^24 ticks (167.8 ms) instead, the bound the R4K CP0 timer
     * next door uses for the identical arithmetic (cpu_mips_timer_update,
     * target/mips/system/cp0_timer.c).
     *
     * The equality case must not arm at @now.  @next == @now makes
     * timer_expired_ns() count expire_time <= current_time as ALREADY
     * EXPIRED, so timerlist_run_timers(), which samples current_time ONCE
     * before its callback loop, pops this timer straight back out, calls in
     * here again, computes the same zero, and never leaves the loop.  It
     * runs that loop holding the BQL, so every vCPU starves behind it and
     * the guest stops dead with the iothread at 100% CPU.  A running
     * virtual clock hides it: @now moves a nanosecond and the loop ends.  A
     * clock that is not running does not, which is why a TCG plugin that
     * freezes QEMU_CLOCK_VIRTUAL to keep its own instrumentation cost out of
     * guest time (cpu_plugin_vclock_pause / the wrong-path excursion freeze)
     * turned this into a permanent wedge -- reproduced on malta -cpu P5600
     * -smp 4, where vptimers[0].comparelo == sh_counterlo + now/TIMER_PERIOD
     * exactly and cpu_ticks_enabled == 0.  Any bound strictly greater than
     * zero ends that loop; 2^24 also bounds the outage.
     *
     * Arming the wrap ends the loop but parks the VP's tick for 42.95 s with
     * nothing scheduled to reprogram it, which is a measured stall mechanism
     * on the CP0 timer -- see the comment on the shared arm there.  The
     * cross-reference in the previous version of this comment said the CP0
     * timer "already does exactly this", meaning the wrap; it no longer
     * does, and the bound moved here to match.  Unlike the CP0 timer this
     * has NOT been measured on a guest: malta -cpu 34Kf has no GIC, so the
     * boot waves that proved the CP0 case never execute this function.
     */
    if (wait == 0 || wait > INT32_MAX) {
        wait = 1 << 24;
    }
    next = now + (uint64_t)wait * TIMER_PERIOD;

    timer_mod(gictimer->vptimers[vp_index].qtimer, next);
}

static void gic_vptimer_expire(MIPSGICTimerState *gictimer, uint32_t vp_index,
                               uint64_t now)
{
    if (gictimer->countstop) {
        /* timer stopped */
        return;
    }
    gictimer->cb(gictimer->opaque, vp_index);
    gic_vptimer_update(gictimer, vp_index, now);
}

static void gic_vptimer_cb(void *opaque)
{
    MIPSGICTimerVPState *vptimer = opaque;
    MIPSGICTimerState *gictimer = vptimer->gictimer;
    gic_vptimer_expire(gictimer, vptimer->vp_index,
                       qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

uint32_t mips_gictimer_get_sh_count(MIPSGICTimerState *gictimer)
{
    int i;
    if (gictimer->countstop) {
        return gictimer->sh_counterlo;
    } else {
        uint64_t now;
        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        for (i = 0; i < gictimer->num_vps; i++) {
            if (timer_pending(gictimer->vptimers[i].qtimer)
                && timer_expired(gictimer->vptimers[i].qtimer, now)) {
                /* The timer has already expired.  */
                gic_vptimer_expire(gictimer, i, now);
            }
        }
        return gictimer->sh_counterlo + (uint32_t)(now / TIMER_PERIOD);
    }
}

void mips_gictimer_store_sh_count(MIPSGICTimerState *gictimer, uint64_t count)
{
    int i;
    uint64_t now;

    if (gictimer->countstop || !gictimer->vptimers[0].qtimer) {
        gictimer->sh_counterlo = count;
    } else {
        /* Store new count register */
        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        gictimer->sh_counterlo = count - (uint32_t)(now / TIMER_PERIOD);
        /* Update timer timer */
        for (i = 0; i < gictimer->num_vps; i++) {
            gic_vptimer_update(gictimer, i, now);
        }
    }
}

uint32_t mips_gictimer_get_vp_compare(MIPSGICTimerState *gictimer,
                                      uint32_t vp_index)
{
    return gictimer->vptimers[vp_index].comparelo;
}

void mips_gictimer_store_vp_compare(MIPSGICTimerState *gictimer,
                                    uint32_t vp_index, uint64_t compare)
{
    gictimer->vptimers[vp_index].comparelo = (uint32_t) compare;
    gic_vptimer_update(gictimer, vp_index,
                       qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

uint8_t mips_gictimer_get_countstop(MIPSGICTimerState *gictimer)
{
    return gictimer->countstop;
}

void mips_gictimer_start_count(MIPSGICTimerState *gictimer)
{
    gictimer->countstop = 0;
    mips_gictimer_store_sh_count(gictimer, gictimer->sh_counterlo);
}

void mips_gictimer_stop_count(MIPSGICTimerState *gictimer)
{
    int i;

    gictimer->countstop = 1;
    /* Store the current value */
    gictimer->sh_counterlo +=
        (uint32_t)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / TIMER_PERIOD);
    for (i = 0; i < gictimer->num_vps; i++) {
        timer_del(gictimer->vptimers[i].qtimer);
    }
}

MIPSGICTimerState *mips_gictimer_init(void *opaque, uint32_t nvps,
                                      MIPSGICTimerCB *cb)
{
    int i;
    MIPSGICTimerState *gictimer = g_new(MIPSGICTimerState, 1);
    gictimer->vptimers = g_new(MIPSGICTimerVPState, nvps);
    gictimer->countstop = 1;
    gictimer->num_vps = nvps;
    gictimer->opaque = opaque;
    gictimer->cb = cb;
    for (i = 0; i < nvps; i++) {
        gictimer->vptimers[i].gictimer = gictimer;
        gictimer->vptimers[i].vp_index = i;
        gictimer->vptimers[i].qtimer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                            &gic_vptimer_cb,
                                            &gictimer->vptimers[i]);
    }
    return gictimer;
}
