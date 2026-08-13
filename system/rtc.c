/*
 * RTC configuration and clock read
 *
 * Copyright (c) 2003-2020 QEMU contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/option.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "system/replay.h"
#include "system/system.h"
#include "system/rtc.h"
#include "hw/rtc/mc146818rtc.h"
#include "qemu/plugin.h"

static enum {
    RTC_BASE_UTC,
    RTC_BASE_LOCALTIME,
    RTC_BASE_DATETIME,
} rtc_base_type = RTC_BASE_UTC;
static time_t rtc_ref_start_datetime;
static int rtc_realtime_clock_offset; /* used only with QEMU_CLOCK_REALTIME */
static int rtc_host_datetime_offset = -1; /* valid & used only with
                                             RTC_BASE_DATETIME */
QEMUClockType rtc_clock;
/***********************************************************/
/* RTC reference time/date access */
static time_t qemu_ref_timedate(QEMUClockType clock)
{
    time_t value = qemu_clock_get_ms(clock) / 1000;
    switch (clock) {
    case QEMU_CLOCK_REALTIME:
        value -= rtc_realtime_clock_offset;
        /* fall through */
    case QEMU_CLOCK_VIRTUAL:
        value += rtc_ref_start_datetime;
        break;
    case QEMU_CLOCK_HOST:
        if (rtc_base_type == RTC_BASE_DATETIME) {
            value -= rtc_host_datetime_offset;
        }
        break;
    default:
        g_assert_not_reached();
    }
    return value;
}

void qemu_get_timedate(struct tm *tm, time_t offset)
{
    time_t ti = qemu_ref_timedate(rtc_clock);

    ti += offset;

    switch (rtc_base_type) {
    case RTC_BASE_DATETIME:
    case RTC_BASE_UTC:
        gmtime_r(&ti, tm);
        break;
    case RTC_BASE_LOCALTIME:
        localtime_r(&ti, tm);
        break;
    }
}

time_t qemu_timedate_diff(struct tm *tm)
{
    time_t seconds;

    switch (rtc_base_type) {
    case RTC_BASE_DATETIME:
    case RTC_BASE_UTC:
        seconds = mktimegm(tm);
        break;
    case RTC_BASE_LOCALTIME:
    {
        struct tm tmp = *tm;
        tmp.tm_isdst = -1; /* use timezone to figure it out */
        seconds = mktime(&tmp);
        break;
    }
    default:
        abort();
    }

    return seconds - qemu_ref_timedate(QEMU_CLOCK_HOST);
}

static void configure_rtc_base_datetime(const char *startdate)
{
    time_t rtc_start_datetime;
    struct tm tm;

    if (sscanf(startdate, "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon,
               &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        /* OK */
    } else if (sscanf(startdate, "%d-%d-%d",
                      &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3) {
        tm.tm_hour = 0;
        tm.tm_min = 0;
        tm.tm_sec = 0;
    } else {
        goto date_fail;
    }
    tm.tm_year -= 1900;
    tm.tm_mon--;
    rtc_start_datetime = mktimegm(&tm);
    if (rtc_start_datetime == -1) {
    date_fail:
        error_report("invalid datetime format");
        error_printf("valid formats: "
                     "'2006-06-17T16:01:21' or '2006-06-17'\n");
        exit(1);
    }
    rtc_host_datetime_offset = rtc_ref_start_datetime - rtc_start_datetime;
    rtc_ref_start_datetime = rtc_start_datetime;
}

void rtc_adopt_vm_clock_for_plugin(void)
{
#ifdef CONFIG_PLUGIN
    /*
     * Guest-time transparency.  A TCG plugin that freezes guest time for its
     * own instrumentation or for a speculative excursion does so with
     * cpu_disable_ticks(), which stops every clock gated on
     * timers_state.cpu_ticks_enabled: QEMU_CLOCK_VIRTUAL and the VM tick
     * counter, and with them the guest TSC, the LAPIC timer, the PIT, the
     * HPET, the ACPI PM timer, Arm's CNTVCT/CNTPCT, MIPS's CP0 Count and the
     * RISC-V ACLINT mtime.  It does NOT stop QEMU_CLOCK_HOST, which is raw
     * host wall time by contract (util/qemu-timer.c, get_clock_realtime) and
     * must stay that way.
     *
     * rtc_clock defaults to QEMU_CLOCK_HOST, and rtc_clock is the ONE clock
     * selector every RTC model reads -- pl031, goldfish-rtc, mc146818,
     * m48t59, ls7a, xlnx-zynqmp and the rest all call
     * qemu_clock_get_ns(rtc_clock).  So with a freezing plugin loaded the
     * board's RTC is the one guest-visible timebase still running through a
     * freeze: its time-of-day advances at host rate while every other guest
     * clock stands still, and its periodic / update / alarm timers keep
     * firing on host time.  A guest that reads the RTC or uses /dev/rtc
     * inside an instrumented window sees a timebase inconsistent with all the
     * others, and Linux's clocksource watchdog compares exactly such pairs.
     *
     * QEMU_CLOCK_VIRTUAL is gated by cpu_ticks_enabled and is already a
     * supported RTC base (-rtc clock=vm), so adopt it when a plugin is
     * present and the user did not ask for a specific clock.  Announced
     * rather than silent: it changes what the guest reads from the RTC.
     *
     * Deciding it HERE, once, off the one global, is the point.  The
     * predecessor made this call inside mc146818rtc_realize, so the machines
     * that get the transparency were the machines that happen to have an
     * mc146818 -- x86 pc/q35 and mips malta.  aarch64 `virt` (pl031) and
     * riscv64 `virt` (goldfish-rtc) instantiate neither, so on exactly those
     * two of the four traced targets rtc_clock stayed QEMU_CLOCK_HOST and the
     * RTC ran at host rate through every excursion.  A per-device decision
     * about a machine-wide global can only ever cover the devices someone
     * thought to patch; this covers every RTC model that exists, including
     * ones not yet written, because they all read rtc_clock.
     *
     * Called from qemu_init_board() after qemu_plugin_load_list() and before
     * machine_run_board_init(): that is the only window in which the plugin
     * set is known and no device has realized yet.  configure_rtc() itself is
     * too early -- it runs during option parsing, before any plugin is
     * loaded.
     */
    if (rtc_clock == QEMU_CLOCK_HOST && qemu_plugin_any_loaded()) {
        warn_report("a TCG plugin is loaded; moving the RTC from "
                    "QEMU_CLOCK_HOST to QEMU_CLOCK_VIRTUAL so it is frozen "
                    "with every other guest clock. Pass -rtc clock=host to "
                    "keep the old behaviour (the guest will then see the RTC "
                    "run through plugin time freezes).");
        rtc_clock = QEMU_CLOCK_VIRTUAL;
    }
#endif
}

void configure_rtc(QemuOpts *opts)
{
    const char *value;

    /* Set defaults */
    rtc_clock = QEMU_CLOCK_HOST;
    rtc_ref_start_datetime = qemu_clock_get_ms(QEMU_CLOCK_HOST) / 1000;
    rtc_realtime_clock_offset = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) / 1000;

    value = qemu_opt_get(opts, "base");
    if (value) {
        if (!strcmp(value, "utc")) {
            rtc_base_type = RTC_BASE_UTC;
        } else if (!strcmp(value, "localtime")) {
            rtc_base_type = RTC_BASE_LOCALTIME;
            replay_add_blocker("-rtc base=localtime");
        } else {
            rtc_base_type = RTC_BASE_DATETIME;
            configure_rtc_base_datetime(value);
        }
    }
    value = qemu_opt_get(opts, "clock");
    if (value) {
        if (!strcmp(value, "host")) {
            rtc_clock = QEMU_CLOCK_HOST;
        } else if (!strcmp(value, "rt")) {
            rtc_clock = QEMU_CLOCK_REALTIME;
        } else if (!strcmp(value, "vm")) {
            rtc_clock = QEMU_CLOCK_VIRTUAL;
        } else {
            error_report("invalid option value '%s'", value);
            exit(1);
        }
    }
    value = qemu_opt_get(opts, "driftfix");
    if (value) {
        if (!strcmp(value, "slew")) {
            object_register_sugar_prop(TYPE_MC146818_RTC,
                                       "lost_tick_policy",
                                       "slew",
                                       false);
            if (!object_class_by_name(TYPE_MC146818_RTC)) {
                warn_report("driftfix 'slew' is not available with this machine");
            }
        } else if (!strcmp(value, "none")) {
            /* discard is default */
        } else {
            error_report("invalid option value '%s'", value);
            exit(1);
        }
    }
}
