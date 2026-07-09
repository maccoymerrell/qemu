/*
 * Wrong-Path Tracing Plugin — WPThreadState definition.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_wp_thread_state.h"

thread_local WPThreadState g_wp_state CST_TLS_HOT;
thread_local bool g_capture_mute CST_TLS_HOT;
